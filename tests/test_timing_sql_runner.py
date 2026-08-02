from __future__ import annotations

from tools import timing_sql_runner as timing
import pytest


def _resp(latency: float, *, status: int = 200, body: str = "ok") -> dict:
    return {
        "status": status,
        "body_text": body,
        "body_size": len(body),
        "headers": "",
        "latency": latency,
        "error": None if status else "transport",
    }


def test_interleaved_timing_requires_stable_repeated_delta(monkeypatch, tmp_path):
    def fake_request(url, **_kwargs):
        return _resp(0.05 if "q=1" in url else 1.5)

    monkeypatch.setattr(timing.core, "_http_request", fake_request)
    summary = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=1",
        param="q",
        variant_value="SLEEP(5)",
        repeat=5,
        max_requests=12,
        min_delta_ms=500,
    )
    assert summary["status"] == "candidate_pending"
    assert summary["statistics"]["sample_count"] == 5
    assert summary["statistics"]["delta_median_ms"] > 500


def test_isolated_slow_sample_does_not_promote(monkeypatch, tmp_path):
    variants = iter([2.0, 0.05, 0.05])

    def fake_request(url, **_kwargs):
        if "q=1" in url:
            return _resp(0.05)
        return _resp(next(variants))

    monkeypatch.setattr(timing.core, "_http_request", fake_request)
    summary = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=1",
        param="q",
        variant_value="SLEEP(5)",
        repeat=3,
        max_requests=8,
        min_delta_ms=500,
    )
    assert summary["status"] == "complete_no_hit"


def test_waf_or_rate_limit_is_partial_not_finding(monkeypatch, tmp_path):
    def fake_request(url, **_kwargs):
        return _resp(0.05, status=429 if "q=1" not in url else 200, body="rate limited")

    monkeypatch.setattr(timing.core, "_http_request", fake_request)
    summary = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=1",
        param="q",
        variant_value="SLEEP(5)",
        repeat=3,
        max_requests=8,
    )
    assert summary["status"] == "partial"
    assert summary["queue"]["status"] == "ok"


def test_baseline_rate_limit_is_partial_not_finding(monkeypatch, tmp_path):
    def fake_request(url, **_kwargs):
        return _resp(0.05, status=429 if "q=1" in url else 200, body="rate limited")

    monkeypatch.setattr(timing.core, "_http_request", fake_request)
    summary = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=1",
        param="q",
        variant_value="SLEEP(5)",
        repeat=3,
        max_requests=8,
    )
    assert summary["status"] == "partial"
    assert all(item["baseline_rate_limited"] for item in summary["samples"])


def test_exact_request_cap_can_finish_when_all_samples_completed(monkeypatch, tmp_path):
    monkeypatch.setattr(timing.core, "_http_request", lambda url, **_: _resp(0.05))
    summary = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=1",
        param="q",
        variant_value="SLEEP(5)",
        repeat=3,
        max_requests=6,
        min_delta_ms=500,
    )
    assert summary["status"] == "complete_no_hit"
    assert summary["request_count"] == 6


def test_timing_rejects_off_target_before_request(monkeypatch, tmp_path):
    monkeypatch.setattr(timing.core, "_http_request", lambda **_: pytest.fail("network must not run"))
    with pytest.raises(ValueError, match="outside target scope"):
        timing.run_timing_sql(
            repo_root=tmp_path,
            target="target.test",
            url="https://other.test/search?q=1",
            param="q",
            variant_value="SLEEP(5)",
        )
