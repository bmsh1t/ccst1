"""
Audit log — tracks every outbound request made during autopilot sessions.

Append-only JSONL file at hunt-memory/audit.jsonl.
Used for post-session review and scope compliance verification.
"""

import fcntl
import json
import os
import sys
import time
from pathlib import Path

from memory.rotation import DEFAULT_KEEP, DEFAULT_MAX_BYTES, rotate_if_needed
from memory.schemas import validate_audit_entry, make_audit_entry, SchemaError


class AuditLog:
    """Append-only audit log for tracking outbound requests."""

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep_backups: int = DEFAULT_KEEP,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.keep_backups = keep_backups

    def log(self, entry: dict) -> None:
        """Validate and append an audit entry."""
        validated = validate_audit_entry(entry)
        line = json.dumps(validated, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        rotate_if_needed(self.path, max_bytes=self.max_bytes, keep=self.keep_backups)

        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                written = os.write(fd, encoded)
                if written != len(encoded):
                    raise OSError(f"Partial write: {written}/{len(encoded)} bytes")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def log_request(
        self,
        url: str,
        method: str,
        scope_check: str,
        response_status: int | None = None,
        finding_id: str | None = None,
        session_id: str | None = None,
        error: str | None = None,
    ) -> None:
        """Convenience method to create and log an audit entry."""
        if session_id is None:
            env_session_id = os.environ.get("BBHUNT_SESSION_ID")
            if env_session_id:
                session_id = env_session_id
        entry = make_audit_entry(
            url=url,
            method=method,
            scope_check=scope_check,
            response_status=response_status,
            finding_id=finding_id,
            session_id=session_id,
            error=error,
        )
        self.log(entry)

    def read_all(self) -> list[dict]:
        """Read all audit entries. Corrupted lines are skipped."""
        if not self.path.exists():
            return []

        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                except json.JSONDecodeError as e:
                    print(
                        f"WARNING: audit line {lineno} is corrupted (skipping): {e}",
                        file=sys.stderr,
                    )
        return entries

    def count_by_session(self, session_id: str) -> dict:
        """Count requests by scope_check status for a session."""
        entries = [e for e in self.read_all() if e.get("session_id") == session_id]
        return {
            "total": len(entries),
            "pass": sum(1 for e in entries if e.get("scope_check") == "pass"),
            "fail": sum(1 for e in entries if e.get("scope_check") == "fail"),
            "errors": sum(1 for e in entries if e.get("error")),
        }


class RateLimiter:
    """Per-host rate limiter for autopilot requests.

    Tracks last request time per host and enforces minimum interval.
    """

    def __init__(self, recon_rps: float = 10.0, test_rps: float = 1.0):
        """
        Args:
            recon_rps: Max requests per second for recon operations.
            test_rps: Max requests per second for vulnerability testing.
        """
        self._last_request: dict[str, float] = {}
        self.recon_interval = 1.0 / recon_rps
        self.test_interval = 1.0 / test_rps

    def wait(self, host: str, is_recon: bool = False) -> float:
        """Wait until the rate limit allows the next request.

        Returns:
            The number of seconds waited.
        """
        interval = self.recon_interval if is_recon else self.test_interval
        now = time.monotonic()
        last = self._last_request.get(host, 0.0)
        elapsed = now - last
        wait_time = max(0.0, interval - elapsed)

        if wait_time > 0:
            time.sleep(wait_time)

        self._last_request[host] = time.monotonic()
        return wait_time


class CircuitBreaker:
    """Simple circuit breaker telemetry for autopilot pacing hints.

    If consecutive_failures reaches threshold, the breaker trips.
    """

    def __init__(self, threshold: int = 5, cooldown: float = 60.0):
        """
        Args:
            threshold: Number of consecutive failures before tripping.
            cooldown: Seconds to wait before retrying after trip.
        """
        self.threshold = threshold
        self.cooldown = cooldown
        self._failures: dict[str, int] = {}
        self._tripped_at: dict[str, float] = {}

    def record_success(self, host: str) -> None:
        """Reset failure count for a host."""
        self._failures[host] = 0
        self._tripped_at.pop(host, None)

    def record_failure(self, host: str) -> bool:
        """Record a failure. Returns True if the breaker just tripped."""
        self._failures[host] = self._failures.get(host, 0) + 1
        if self._failures[host] >= self.threshold:
            self._tripped_at[host] = time.monotonic()
            return True
        return False

    def is_tripped(self, host: str) -> bool:
        """Check if the breaker is tripped for a host."""
        if host not in self._tripped_at:
            return False
        elapsed = time.monotonic() - self._tripped_at[host]
        if elapsed >= self.cooldown:
            # Cooldown expired — allow one retry
            self._failures[host] = self.threshold - 1
            del self._tripped_at[host]
            return False
        return True

    def get_status(self, host: str) -> dict:
        """Get the current status for a host."""
        return {
            "host": host,
            "failures": self._failures.get(host, 0),
            "tripped": self.is_tripped(host),
            "threshold": self.threshold,
        }


class SafeMethodPolicy:
    """Track HTTP method risk hints for autopilot mode.

    Default safe methods remain GET/HEAD/OPTIONS, but the policy is advisory
    only. Unsafe methods are flagged in the returned metadata instead of being
    blocked or requiring a separate approval step.
    """

    DEFAULT_SAFE = {"GET", "HEAD", "OPTIONS"}

    def __init__(
        self,
        safe_methods: set[str] | None = None,
        enabled: bool = True,
    ):
        self._safe = {m.upper() for m in (safe_methods if safe_methods is not None else self.DEFAULT_SAFE)}
        self._enabled = enabled

    def is_safe(self, method: str) -> bool:
        """Return True if the method is safe to send without approval."""
        if not self._enabled:
            return True
        return method.upper() in self._safe

    def check(self, method: str, url: str) -> dict:
        """Return a structured advisory payload for the given method + URL."""
        method_upper = method.upper()
        if self.is_safe(method_upper):
            return {"decision": "allow", "method": method_upper, "url": url}
        return {
            "decision": "allow",
            "method": method_upper,
            "url": url,
            "advisory": True,
            "reason": f"Unsafe method {method_upper} recorded as advisory only",
        }


class AutopilotGuard:
    """Unified pre-request guard for autopilot mode.

    Integrates CircuitBreaker + RateLimiter + SafeMethodPolicy into a single
    check_request() call that always allows execution while surfacing advisory
    telemetry such as circuit-breaker state and unsafe methods.
    """

    def __init__(
        self,
        circuit_threshold: int = 5,
        circuit_cooldown: float = 60.0,
        recon_rps: float = 10.0,
        test_rps: float = 1.0,
        safe_methods_only: bool = True,
        safe_methods: set[str] | None = None,
    ):
        self._breaker = CircuitBreaker(
            threshold=circuit_threshold,
            cooldown=circuit_cooldown,
        )
        self._limiter = RateLimiter(recon_rps=recon_rps, test_rps=test_rps)
        self._method_policy = SafeMethodPolicy(
            safe_methods=safe_methods,
            enabled=safe_methods_only,
        )

    @staticmethod
    def _extract_host(url: str) -> str:
        """Extract host (with port) from a URL."""
        # Strip scheme
        if "://" in url:
            url = url.split("://", 1)[1]
        # Strip path
        host = url.split("/", 1)[0]
        # Strip userinfo
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        return host

    def check_request(self, method: str, url: str) -> dict:
        """Check whether a request should proceed.

        Returns:
            dict with 'decision' key fixed to 'allow'. Additional advisory
            fields explain any breaker or method-policy warnings.
        """
        host = self._extract_host(url)
        advisories: list[str] = []

        if self._breaker.is_tripped(host):
            advisories.append(f"Circuit breaker advisory for {host}")

        method_check = self._method_policy.check(method, url)
        if method_check.get("advisory"):
            advisories.append(str(method_check.get("reason") or "Unsafe method advisory"))

        result = {
            "decision": "allow",
            "method": method.upper(),
            "url": url,
            "host": host,
        }
        if advisories:
            result["advisories"] = advisories
            result["reason"] = "; ".join(advisories)
        return result

    def record_failure(self, host: str) -> bool:
        """Record a failure for circuit breaker. Returns True if breaker just tripped."""
        return self._breaker.record_failure(host)

    def record_success(self, host: str) -> None:
        """Record a success — resets circuit breaker for the host."""
        self._breaker.record_success(host)

    def get_host_status(self, host: str) -> dict:
        """Get circuit breaker status for a host."""
        cb_status = self._breaker.get_status(host)
        return {
            "host": host,
            "failures": cb_status["failures"],
            "circuit_tripped": cb_status["tripped"],
            "circuit_threshold": cb_status["threshold"],
        }
