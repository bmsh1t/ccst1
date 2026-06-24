"""Tests for AutopilotGuard — unified pre-request guard for autopilot mode."""

import time
import pytest

from memory.audit_log import (
    AutopilotGuard,
    CircuitBreaker,
    RateLimiter,
    SafeMethodPolicy,
)


class TestAutopilotGuardAllow:
    """Safe requests on healthy hosts should be allowed."""

    def test_safe_get_on_healthy_host(self):
        guard = AutopilotGuard()
        result = guard.check_request("GET", "https://target.com/api/users")
        assert result["decision"] == "allow"

    def test_safe_head_allowed(self):
        guard = AutopilotGuard()
        result = guard.check_request("HEAD", "https://target.com/")
        assert result["decision"] == "allow"

    def test_safe_options_allowed(self):
        guard = AutopilotGuard()
        result = guard.check_request("OPTIONS", "https://target.com/api")
        assert result["decision"] == "allow"


class TestAutopilotGuardUnsafeMethods:
    """Unsafe methods should surface advisories without blocking."""

    def test_post_returns_allow_with_advisory(self):
        guard = AutopilotGuard()
        result = guard.check_request("POST", "https://target.com/api/users")
        assert result["decision"] == "allow"
        assert "unsafe method" in result["reason"].lower() or "method" in result["reason"].lower()
        assert result["advisories"]

    def test_put_returns_allow_with_advisory(self):
        guard = AutopilotGuard()
        result = guard.check_request("PUT", "https://target.com/api/users/1")
        assert result["decision"] == "allow"
        assert result["advisories"]

    def test_delete_returns_allow_with_advisory(self):
        guard = AutopilotGuard()
        result = guard.check_request("DELETE", "https://target.com/api/users/1")
        assert result["decision"] == "allow"
        assert result["advisories"]

    def test_patch_returns_allow_with_advisory(self):
        guard = AutopilotGuard()
        result = guard.check_request("PATCH", "https://target.com/api/users/1")
        assert result["decision"] == "allow"
        assert result["advisories"]


class TestAutopilotGuardCircuitBreaker:
    """Requests to tripped hosts should surface advisories without blocking."""

    def test_allow_when_circuit_tripped_with_advisory(self):
        guard = AutopilotGuard(circuit_threshold=2)
        # Trip the breaker
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        result = guard.check_request("GET", "https://target.com/api")
        assert result["decision"] == "allow"
        assert "circuit" in result["reason"].lower() or "tripped" in result["reason"].lower()

    def test_advisory_clears_after_cooldown(self):
        guard = AutopilotGuard(circuit_threshold=2, circuit_cooldown=0.1)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        first = guard.check_request("GET", "https://target.com/api")
        assert first["decision"] == "allow"
        assert "advisories" in first
        time.sleep(0.15)
        second = guard.check_request("GET", "https://target.com/api")
        assert second["decision"] == "allow"
        assert "advisories" not in second

    def test_success_resets_breaker(self):
        guard = AutopilotGuard(circuit_threshold=3)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        guard.record_success("target.com")
        guard.record_failure("target.com")
        # Only 1 failure after reset — not tripped
        result = guard.check_request("GET", "https://target.com/api")
        assert result["decision"] == "allow"

    def test_different_hosts_independent(self):
        guard = AutopilotGuard(circuit_threshold=2)
        guard.record_failure("bad.com")
        guard.record_failure("bad.com")
        bad = guard.check_request("GET", "https://bad.com/api")
        # bad.com is tripped, but good.com is fine
        assert bad["decision"] == "allow"
        assert bad["advisories"]
        assert guard.check_request("GET", "https://good.com/api")["decision"] == "allow"


class TestAutopilotGuardHostExtraction:
    """Guard should extract host from URL for circuit breaker checks."""

    def test_extracts_host_from_https(self):
        guard = AutopilotGuard(circuit_threshold=2)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        result = guard.check_request("GET", "https://target.com/api/users")
        assert result["decision"] == "allow"
        assert result["advisories"]

    def test_extracts_host_with_port(self):
        guard = AutopilotGuard(circuit_threshold=2)
        guard.record_failure("target.com:8080")
        guard.record_failure("target.com:8080")
        result = guard.check_request("GET", "https://target.com:8080/api")
        assert result["decision"] == "allow"
        assert result["advisories"]


class TestAutopilotGuardCombined:
    """Multiple guards interact correctly and remain advisory-only."""

    def test_circuit_breaker_adds_advisory(self):
        """If host is tripped, keep the circuit-breaker advisory for safe methods."""
        guard = AutopilotGuard(circuit_threshold=2)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        result = guard.check_request("GET", "https://target.com/api")
        assert result["decision"] == "allow"
        assert any("circuit" in item.lower() for item in result["advisories"])

    def test_unsafe_method_on_healthy_host(self):
        """Healthy host + unsafe method = advisory, not block."""
        guard = AutopilotGuard()
        result = guard.check_request("DELETE", "https://target.com/api/users/1")
        assert result["decision"] == "allow"
        assert result["advisories"]

    def test_unsafe_method_on_tripped_host(self):
        """Tripped host + unsafe method = combined advisories."""
        guard = AutopilotGuard(circuit_threshold=2)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        result = guard.check_request("DELETE", "https://target.com/api")
        assert result["decision"] == "allow"
        assert len(result["advisories"]) >= 2


class TestAutopilotGuardStatus:
    """Getting guard status for a host."""

    def test_status_healthy(self):
        guard = AutopilotGuard()
        status = guard.get_host_status("target.com")
        assert status["circuit_tripped"] is False
        assert status["failures"] == 0

    def test_status_after_failures(self):
        guard = AutopilotGuard(circuit_threshold=5)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        status = guard.get_host_status("target.com")
        assert status["failures"] == 2
        assert status["circuit_tripped"] is False

    def test_status_tripped(self):
        guard = AutopilotGuard(circuit_threshold=2)
        guard.record_failure("target.com")
        guard.record_failure("target.com")
        status = guard.get_host_status("target.com")
        assert status["circuit_tripped"] is True


class TestAutopilotGuardDisabledPolicy:
    """When safe_methods_only is disabled, all methods pass method check."""

    def test_disabled_allows_delete(self):
        guard = AutopilotGuard(safe_methods_only=False)
        result = guard.check_request("DELETE", "https://target.com/api/users/1")
        assert result["decision"] == "allow"
