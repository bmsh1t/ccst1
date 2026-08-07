"""Spray Shell 兼容入口的参数与 dry-run 回归。"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    spec = tmp_path / "request.json"
    users.write_text("alice@example.test\n", encoding="utf-8")
    passes.write_text("Secret#1\n", encoding="utf-8")
    passes.chmod(0o600)
    spec.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "method": "POST",
                "url": "http://127.0.0.1:9/login",
                "headers": {},
                "body_format": "form",
                "body": {"username": "{USER}", "password": "{PASS}"},
                "success": {},
                "failure": {"body_regex": "Invalid"},
            }
        ),
        encoding="utf-8",
    )
    return users, passes, spec


def test_orchestrator_dry_run_dispatches_without_network(tmp_path: Path):
    users, passes, spec = _inputs(tmp_path)
    script = Path(__file__).resolve().parents[1] / "tools" / "spray_orchestrator.sh"

    completed = subprocess.run(
        [
            str(script),
            "http://127.0.0.1:9/login",
            "--mode",
            "http-form",
            "--users",
            str(users),
            "--passes",
            str(passes),
            "--request-spec",
            str(spec),
            "--dry-run",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "network attempts=0" in completed.stdout
    assert len(list(tmp_path.glob("recon/*/spray/preflight-*.json"))) == 1


def test_orchestrator_dry_run_displays_deduped_cardinality_limits(tmp_path: Path):
    users, passes, spec = _inputs(tmp_path)
    users.write_text("alice@example.test\nalice@example.test\nbob@example.test\n", encoding="utf-8")
    passes.write_text("Secret#1\nSecret#1\nSecret#2\n", encoding="utf-8")
    passes.chmod(0o600)
    script = Path(__file__).resolve().parents[1] / "tools" / "spray_orchestrator.sh"

    completed = subprocess.run(
        [
            str(script),
            "http://127.0.0.1:9/login",
            "--mode",
            "http-form",
            "--users",
            str(users),
            "--passes",
            str(passes),
            "--request-spec",
            str(spec),
            "--max-users",
            "2",
            "--max-attempts",
            "4",
            "--dry-run",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert any(line.strip().endswith("4") and "Total attempts:" in line for line in completed.stdout.splitlines())
    assert any(line.strip().endswith("2") and "Max users:" in line for line in completed.stdout.splitlines())
    assert any(line.strip().endswith("4") and "Max attempts:" in line for line in completed.stdout.splitlines())
    payload = json.loads(next(tmp_path.glob("recon/*/spray/preflight-*.json")).read_text(encoding="utf-8"))
    assert payload["binding"]["user_count"] == 2
    assert payload["binding"]["password_count"] == 2
    assert payload["binding"]["total_attempts"] == 4
    assert payload["binding"]["max_users"] == 2
    assert payload["binding"]["max_attempts"] == 4


def test_orchestrator_rejects_user_cardinality_before_creating_run(tmp_path: Path):
    users, passes, spec = _inputs(tmp_path)
    users.write_text("alice@example.test\nbob@example.test\n", encoding="utf-8")
    script = Path(__file__).resolve().parents[1] / "tools" / "spray_orchestrator.sh"

    completed = subprocess.run(
        [
            str(script),
            "http://127.0.0.1:9/login",
            "--mode",
            "http-form",
            "--users",
            str(users),
            "--passes",
            str(passes),
            "--request-spec",
            str(spec),
            "--max-users",
            "1",
            "--dry-run",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "2" in completed.stderr and "1" in completed.stderr
    assert not (tmp_path / "recon").exists()


def test_orchestrator_rejects_attempt_cardinality_before_creating_run(tmp_path: Path):
    users, passes, spec = _inputs(tmp_path)
    users.write_text("alice@example.test\nbob@example.test\n", encoding="utf-8")
    passes.write_text("Secret#1\nSecret#2\n", encoding="utf-8")
    passes.chmod(0o600)
    script = Path(__file__).resolve().parents[1] / "tools" / "spray_orchestrator.sh"

    completed = subprocess.run(
        [
            str(script),
            "http://127.0.0.1:9/login",
            "--mode",
            "http-form",
            "--users",
            str(users),
            "--passes",
            str(passes),
            "--request-spec",
            str(spec),
            "--max-attempts",
            "3",
            "--dry-run",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "4" in completed.stderr and "3" in completed.stderr
    assert not (tmp_path / "recon").exists()


def test_orchestrator_unattended_live_rejects_missing_preflight(tmp_path: Path):
    users, passes, spec = _inputs(tmp_path)
    script = Path(__file__).resolve().parents[1] / "tools" / "spray_orchestrator.sh"

    completed = subprocess.run(
        [
            str(script),
            "http://127.0.0.1:9/login",
            "--mode",
            "http-form",
            "--users",
            str(users),
            "--passes",
            str(passes),
            "--request-spec",
            str(spec),
            "--i-understand",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "requires --preflight" in completed.stderr


def test_orchestrator_rejects_mode_specific_flag_conflicts(tmp_path: Path):
    users, passes, _ = _inputs(tmp_path)
    script = Path(__file__).resolve().parents[1] / "tools" / "spray_orchestrator.sh"

    completed = subprocess.run(
        [
            str(script),
            "https://login.example.test/token",
            "--mode",
            "oauth",
            "--users",
            str(users),
            "--passes",
            str(passes),
            "--fail-regex",
            "Invalid",
            "--dry-run",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "only valid with --mode http-form" in completed.stderr

    completed = subprocess.run(
        [
            str(script),
            "https://login.example.test",
            "--mode",
            "o365",
            "--users",
            str(users),
            "--passes",
            str(passes),
            "--insecure",
            "--dry-run",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "--insecure is only valid" in completed.stderr
