"""Tests for tools/request_guard.py."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from memory.audit_log import AuditLog
from memory.target_profile import make_target_profile, save_target_profile
from request_guard import (
    format_guard_output,
    guard_state_path,
    load_guard_state,
    load_guard_status,
    preflight_request,
    record_request,
    save_guard_state,
)


def _save_profile(tmp_hunt_dir, target="target.com", scope_snapshot=None):
    save_target_profile(
        tmp_hunt_dir,
        make_target_profile(
            target,
            scope_snapshot=scope_snapshot
            or {
                "in_scope": ["target.com", "*.target.com", "api.target.com"],
                "out_of_scope": ["blog.target.com"],
                "excluded_classes": ["dos"],
            },
        ),
    )


class TestRequestGuardPersistence:

    def test_corrupt_json_fails_with_path_without_rebuild(self, tmp_hunt_dir):
        path = guard_state_path(tmp_hunt_dir, "target.com")
        path.parent.mkdir(parents=True)
        path.write_text("{broken", encoding="utf-8")
        original = path.read_bytes()

        with pytest.raises(ValueError, match="invalid request guard state JSON") as exc_info:
            preflight_request(
                memory_dir=tmp_hunt_dir,
                target="target.com",
                url="https://target.com/",
                method="GET",
                sleep=False,
                now_ts=100.0,
            )

        assert str(path) in str(exc_info.value)
        assert path.read_bytes() == original

    def test_invalid_state_shape_fails_with_path(self, tmp_hunt_dir):
        path = guard_state_path(tmp_hunt_dir, "target.com")
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"target": "target.com", "hosts": []}), encoding="utf-8")

        with pytest.raises(ValueError, match="hosts must be an object") as exc_info:
            load_guard_state(tmp_hunt_dir, "target.com")

        assert str(path) in str(exc_info.value)

    def test_atomic_replace_failure_preserves_old_state_and_retry_converges(
        self,
        tmp_hunt_dir,
        monkeypatch,
    ):
        old_state = {
            "settings": {"breaker_threshold": 2},
            "hosts": {"api.target.com": {"failures": 1}},
        }
        path = save_guard_state(tmp_hunt_dir, "target.com", old_state)
        old_bytes = path.read_bytes()
        new_state = {
            "settings": {"breaker_threshold": 2},
            "hosts": {"api.target.com": {"failures": 2}},
        }
        real_replace = Path.replace

        def fail_replace(_self, _target):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(Path, "replace", fail_replace)
        with pytest.raises(OSError, match="simulated replace failure"):
            save_guard_state(tmp_hunt_dir, "target.com", new_state)

        assert path.read_bytes() == old_bytes
        assert not list(path.parent.glob(f".{path.name}.*.tmp"))

        monkeypatch.setattr(Path, "replace", real_replace)
        save_guard_state(tmp_hunt_dir, "target.com", new_state)
        assert load_guard_state(tmp_hunt_dir, "target.com")["hosts"]["api.target.com"]["failures"] == 2

    def test_cli_reports_corrupt_state_without_traceback(self, tmp_hunt_dir):
        path = guard_state_path(tmp_hunt_dir, "target.com")
        path.parent.mkdir(parents=True)
        path.write_text("{broken", encoding="utf-8")
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parents[1] / "tools" / "request_guard.py"),
                "status",
                "--memory-dir",
                str(tmp_hunt_dir),
                "--target",
                "target.com",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        assert completed.returncode == 2
        assert str(path) in completed.stderr
        assert "Traceback" not in completed.stderr


class TestRequestGuardPreflight:

    def test_marks_non_matching_target_as_advisory(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir)

        result = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://evil.com/api",
            method="GET",
            session_id="sess-1",
            sleep=False,
            now_ts=100.0,
        )

        assert result["allowed"] is True
        assert result["action"] == "allow_advisory"
        assert result["scope_check"] == "fail"
        assert "target-match advisory" in result["reason"].lower()

        entries = AuditLog(tmp_hunt_dir / "audit.jsonl").read_all()
        assert entries == []

    def test_marks_unsafe_yolo_method_as_advisory(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir)

        result = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/api/v1/users/1",
            method="PATCH",
            mode="yolo",
            sleep=False,
            now_ts=100.0,
        )

        assert result["allowed"] is True
        assert result["action"] == "allow_advisory"
        assert "side-effect-capable method advisory" in result["reason"].lower()

    def test_uses_persisted_rate_limit_window(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "test_rps": 2})

        first = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            sleep=False,
            now_ts=100.0,
        )
        second = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            sleep=False,
            now_ts=100.2,
        )

        assert first["allowed"] is True
        assert first["wait_seconds"] == 0.0
        assert second["allowed"] is True
        assert second["wait_seconds"] == 0.0
        assert second["suggested_wait_seconds"] == 0.3

        output = format_guard_output(second, "preflight")
        assert "Suggested wait: 0.300s" in output
        assert "Wait: 0.000s" not in output

    def test_localhost_target_inputs_stay_valid_without_special_mode(self, tmp_hunt_dir):
        result = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="127.0.0.1",
            url="https://127.0.0.1:8080/admin",
            method="PATCH",
            mode="yolo",
            sleep=False,
            now_ts=100.0,
        )

        assert result["allowed"] is True
        assert result["action"] == "allow_advisory"
        assert result["scope_check"] == "pass"
        assert result["wait_seconds"] == 0.0
        assert "side-effect-capable method advisory" in result["reason"].lower()


class TestRequestGuardRecord:

    def test_trips_breaker_and_marks_follow_up_request_as_advisory(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "breaker_threshold": 2, "breaker_cooldown": 30})

        first = record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=403,
            now_ts=100.0,
        )
        second = record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            error="timeout",
            now_ts=105.0,
        )
        blocked = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            sleep=False,
            now_ts=110.0,
        )

        assert first["action"] == "failure"
        assert second["action"] == "tripped"
        assert second["breaker"]["tripped"] is True
        assert blocked["allowed"] is True
        assert blocked["action"] == "allow_advisory"
        assert "circuit breaker advisory" in blocked["reason"].lower()
        assert blocked["breaker"]["remaining_seconds"] == 25.0

    def test_success_resets_failures(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "breaker_threshold": 3})

        record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            now_ts=100.0,
        )
        result = record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=200,
            now_ts=101.0,
        )

        assert result["action"] == "success"
        assert result["breaker"]["failures"] == 0
        assert result["breaker"]["tripped"] is False

    def test_status_reports_tracked_hosts(self, tmp_hunt_dir):
        _save_profile(tmp_hunt_dir, scope_snapshot={"in_scope": ["api.target.com"], "breaker_threshold": 2, "breaker_cooldown": 30})

        record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=403,
            now_ts=100.0,
        )

        status = load_guard_status(tmp_hunt_dir, "target.com", breaker_threshold=2, now_ts=105.0)
        assert status["tracked_hosts"] == 1
        assert status["tripped_hosts"] == 0
        assert status["ready_hosts"] == 1
        assert status["hosts"][0]["host"] == "api.target.com"
        assert status["hosts"][0]["failures"] == 1

    def test_status_reports_tripped_and_ready_counts(self, tmp_hunt_dir):
        _save_profile(
            tmp_hunt_dir,
            scope_snapshot={"in_scope": ["*.target.com"], "breaker_threshold": 1, "breaker_cooldown": 30},
        )

        record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://api.target.com/graphql",
            method="GET",
            response_status=429,
            now_ts=100.0,
        )
        record_request(
            memory_dir=tmp_hunt_dir,
            target="target.com",
            url="https://files.target.com/download?id=1",
            method="GET",
            response_status=200,
            now_ts=101.0,
        )

        status = load_guard_status(tmp_hunt_dir, "target.com", now_ts=105.0)
        assert status["tracked_hosts"] == 2
        assert status["tripped_hosts"] == 1
        assert status["ready_hosts"] == 1

    def test_localhost_target_uses_standard_breaker_telemetry(self, tmp_hunt_dir):
        first = record_request(
            memory_dir=tmp_hunt_dir,
            target="127.0.0.1",
            url="https://127.0.0.1:8080/admin",
            method="PATCH",
            response_status=403,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=100.0,
        )
        second = preflight_request(
            memory_dir=tmp_hunt_dir,
            target="127.0.0.1",
            url="https://127.0.0.1:8080/admin",
            method="DELETE",
            mode="yolo",
            breaker_threshold=1,
            breaker_cooldown=30,
            sleep=False,
            now_ts=101.0,
        )

        assert first["action"] == "tripped"
        assert first["scope_check"] == "pass"
        assert second["allowed"] is True
        assert second["action"] == "allow_advisory"
        assert "circuit breaker advisory" in second["reason"].lower()

        status = load_guard_status(tmp_hunt_dir, "127.0.0.1", now_ts=102.0)
        assert status["tracked_hosts"] == 1
        assert status["hosts"][0]["tripped"] is True
        assert status["hosts"][0]["failures"] == 1

    def test_status_reads_host_list_state_from_relative_target(self, tmp_hunt_dir, tmp_path, monkeypatch):
        list_file = tmp_path / "scope.txt"
        list_file.write_text("api.target.com\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        record_request(
            memory_dir=tmp_hunt_dir,
            target=str(list_file.resolve()),
            url="https://api.target.com/graphql",
            method="GET",
            response_status=403,
            breaker_threshold=1,
            breaker_cooldown=30,
            now_ts=100.0,
        )

        status = load_guard_status(tmp_hunt_dir, "scope.txt", now_ts=101.0)

        assert status["tracked_hosts"] == 1
        assert status["tripped_hosts"] == 1
        assert status["hosts"][0]["host"] == "api.target.com"
        assert status["hosts"][0]["tripped"] is True
