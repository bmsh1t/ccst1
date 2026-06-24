"""tests/test_audit_log_parallel.py — B6 R10 shared rate-limiter semantics.

Verifies that:
  * GlobalRateLimiter serializes concurrent workers via fcntl.flock
  * Per-worker sub-budget is derived from worker_count + safety margin
  * Existing non-parallel audit-log shape is unchanged
"""

from __future__ import annotations

import json
import multiprocessing
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.parallel_workers import GlobalRateLimiter
from memory.audit_log import RateLimiter as InProcRateLimiter


# ---------------------------------------------------------------------
#  Rate limiter math
# ---------------------------------------------------------------------

class TestPerWorkerInterval:
    def test_single_worker_matches_base_rate(self, tmp_path):
        # 1 worker, 1 rps test budget, no safety → interval ≈ 1.0s
        limiter = GlobalRateLimiter(
            tmp_path / "lock.json", test_rps=1.0,
            worker_count=1, safety_margin=0.0,
        )
        assert abs(limiter._per_worker_interval(1.0) - 1.0) < 0.001

    def test_two_workers_double_interval_plus_margin(self, tmp_path):
        # 2 workers, 1 rps base, 10% margin → 1.0 × 2 × 1.10 = 2.2s each
        limiter = GlobalRateLimiter(
            tmp_path / "lock.json", test_rps=1.0,
            worker_count=2, safety_margin=0.10,
        )
        assert abs(limiter._per_worker_interval(1.0) - 2.2) < 0.001

    def test_zero_worker_count_falls_back_to_one(self, tmp_path):
        limiter = GlobalRateLimiter(
            tmp_path / "lock.json", test_rps=1.0, worker_count=0,
        )
        # max(1, 0) = 1
        assert limiter.worker_count == 1


# ---------------------------------------------------------------------
#  Cross-process serialization via fcntl.flock
# ---------------------------------------------------------------------

def _hammer(state_path_str: str, host: str, count: int):
    """Worker entrypoint (must be top-level for multiprocessing pickling)."""
    sys.path.insert(0, str(REPO_ROOT))
    from tools.parallel_workers import GlobalRateLimiter
    limiter = GlobalRateLimiter(
        state_path_str, test_rps=1000.0, worker_count=2, safety_margin=0.0,
    )
    for _ in range(count):
        limiter.wait(host, sleep=lambda _s: None)


class TestCrossProcessLock:
    def test_two_processes_do_not_corrupt_state_file(self, tmp_path):
        state = tmp_path / "lock.json"
        state.write_text("{}")
        host = "h1.test"
        procs = [
            multiprocessing.Process(target=_hammer, args=(str(state), host, 30))
            for _ in range(2)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=15)
            assert p.exitcode == 0, "worker crashed"
        # Final state file must still parse and contain the host entry
        data = json.loads(state.read_text())
        assert host in data
        assert "last_request_epoch" in data[host]


# ---------------------------------------------------------------------
#  In-process limiter still works for non-parallel mode
# ---------------------------------------------------------------------

class TestNonParallelUnchanged:
    def test_in_process_rate_limiter_still_present(self):
        """C1 — single-thread autopilot uses memory.audit_log.RateLimiter."""
        limiter = InProcRateLimiter(test_rps=10.0)
        slept = limiter.wait("h.test")
        assert slept >= 0.0


# ---------------------------------------------------------------------
#  Audit schema additivity
# ---------------------------------------------------------------------

class TestAuditSchemaAdditivity:
    def test_extras_can_be_attached_without_validation_error(self):
        from memory.schemas import make_audit_entry, validate_audit_entry
        base = make_audit_entry(
            url="https://x.example/api",
            method="GET",
            scope_check="pass",
            response_status=200,
            session_id="s1",
        )
        # Attach worker_id + parent_session — these are advisory extras
        # (additive to the schema) and should not cause validation to fail.
        base["worker_id"] = "w1"
        base["parent_session"] = "p-sess"
        validated = validate_audit_entry(base)
        # The validated entry should not be empty
        assert validated.get("session_id") == "s1"
        assert validated.get("worker_id") == "w1"
        assert validated.get("parent_session") == "p-sess"
