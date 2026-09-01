from __future__ import annotations

from tools import timing_sql_runner as timing
from tools.action_queue import load_queue
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

    monkeypatch.setattr(timing, "_http_request", fake_request)
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

    monkeypatch.setattr(timing, "_http_request", fake_request)
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

    monkeypatch.setattr(timing, "_http_request", fake_request)
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

    monkeypatch.setattr(timing, "_http_request", fake_request)
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
    monkeypatch.setattr(timing, "_http_request", lambda url, **_: _resp(0.05))
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
    monkeypatch.setattr(timing, "_http_request", lambda **_: pytest.fail("network must not run"))
    with pytest.raises(ValueError, match="outside target scope"):
        timing.run_timing_sql(
            repo_root=tmp_path,
            target="target.test",
            url="https://other.test/search?q=1",
            param="q",
            variant_value="SLEEP(5)",
        )


def test_timing_request_error_keeps_action_non_terminal(monkeypatch, tmp_path):
    monkeypatch.setattr(
        timing,
        "_http_request",
        lambda **_: (_ for _ in ()).throw(RuntimeError("fixture failure")),
    )
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
    assert summary["queue"]["action_status"] == "running"


def test_timing_recovery_hint_redacts_values(monkeypatch, tmp_path):
    monkeypatch.setattr(timing, "_http_request", lambda url, **_: _resp(0.05))
    summary = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=SECRET",
        param="q",
        variant_value="SECRET_PAYLOAD",
        baseline_value="SECRET",
        repeat=3,
        max_requests=6,
    )

    assert summary["status"] == "complete_no_hit"
    action = load_queue(tmp_path, "target.test")["actions"][0]
    assert "SECRET" not in action["command_hint"]
    assert "SECRET" not in action["action"]
    assert "PAYLOAD" in action["command_hint"]


def test_timing_generation_identity_and_terminal_replay(monkeypatch, tmp_path):
    calls = []

    def fake_request(url, **_kwargs):
        calls.append(url)
        return _resp(0.05)

    monkeypatch.setattr(timing, "_http_request", fake_request)
    first = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=1",
        param="q",
        variant_value="SLEEP(5)",
        repeat=3,
        max_requests=6,
    )
    first_call_count = len(calls)
    replay = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=1",
        param="q",
        variant_value="SLEEP(5)",
        repeat=3,
        max_requests=6,
    )
    second = timing.run_timing_sql(
        repo_root=tmp_path,
        target="target.test",
        url="https://target.test/search?q=1",
        param="q",
        variant_value="SLEEP(6)",
        repeat=3,
        max_requests=6,
    )

    assert first["status"] == replay["status"] == "complete_no_hit"
    assert len(calls) == first_call_count + 6
    actions = [item for item in load_queue(tmp_path, "target.test")["actions"] if item["source"] == "sql-timing"]
    assert len(actions) == 2
    assert len({item["source_id"] for item in actions}) == 2
