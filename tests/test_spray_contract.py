"""Spray preflight/run 绑定与恢复契约。"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from tools.spray_contract import append_attempt, finish_run, password_hash_prefix, prepare_run


def _set_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    users.write_text("alice@example.test\nalice@example.test\n", encoding="utf-8")
    passes.write_text("Secret#1\n", encoding="utf-8")
    passes.chmod(0o600)
    values = {
        "SPRAY_REPO_ROOT": str(tmp_path),
        "SPRAY_MODE": "oauth",
        "SPRAY_TARGET_URL": "https://login.example.test/token",
        "SPRAY_USERS_FILE": str(users),
        "SPRAY_PASSES_FILE": str(passes),
        "SPRAY_DELAY": "0",
        "SPRAY_JITTER": "0",
        "SPRAY_CONTINUE_ON_HIT": "false",
        "SPRAY_DRY_RUN": "true",
        "SPRAY_I_UNDERSTAND": "true",
        "SPRAY_PREFLIGHT": "",
        "SPRAY_RESUME": "",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return users, passes


def test_preflight_binds_inputs_and_resume_skips_recorded_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _, passes = _set_env(monkeypatch, tmp_path)
    binding = {"grant_type": "password"}
    shape = {"grant_type": "password"}

    dry = prepare_run("oauth", config_binding=binding, request_shape=shape)
    assert dry.dry_run is True
    assert dry.preflight_path is not None
    assert stat.S_IMODE(dry.preflight_path.stat().st_mode) == 0o600

    monkeypatch.setenv("SPRAY_DRY_RUN", "false")
    monkeypatch.setenv("SPRAY_PREFLIGHT", str(dry.preflight_path))
    live = prepare_run("oauth", config_binding=binding, request_shape=shape)
    attempt_key = live.attempt_key("alice@example.test", "Secret#1")
    append_attempt(
        live,
        {
            "tool": "builtin",
            "round": 1,
            "user": "alice@example.test",
            "pwd_sha256_prefix": attempt_key.rsplit("\0", 1)[1],
            "attempt_key": attempt_key,
            "classification": "invalid_credentials",
            "credential_valid": False,
            "token_issued": False,
            "status_code": 400,
            "duration_ms": 1,
        },
    )
    finish_run(live, status="interrupted", stop_reason="sigint", counters={}, exit_code=130)

    monkeypatch.setenv("SPRAY_PREFLIGHT", "")
    monkeypatch.setenv("SPRAY_RESUME", str(live.run_dir))
    resumed = prepare_run("oauth", config_binding=binding, request_shape=shape)
    assert attempt_key in resumed.completed_attempts
    finish_run(resumed, status="interrupted", stop_reason="sigint", counters={}, exit_code=130)

    passes.write_text("Changed#1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="resume binding mismatch"):
        prepare_run("oauth", config_binding=binding, request_shape=shape)


def test_unattended_live_requires_preflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _set_env(monkeypatch, tmp_path)
    monkeypatch.setenv("SPRAY_DRY_RUN", "false")

    with pytest.raises(ValueError, match="requires --preflight"):
        prepare_run("oauth", config_binding={}, request_shape={})


def test_preflight_contains_no_plaintext_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _set_env(monkeypatch, tmp_path)

    context = prepare_run(
        "oauth",
        config_binding={"client_secret_sha256": "digest"},
        request_shape={"client_secret_set": True},
    )

    raw = context.preflight_path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    assert "Secret#1" not in raw
    assert payload["binding"]["user_count"] == 1


def test_expired_preflight_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _set_env(monkeypatch, tmp_path)
    dry = prepare_run("oauth", config_binding={}, request_shape={})
    payload = json.loads(dry.preflight_path.read_text(encoding="utf-8"))
    payload["expires_at"] = "2000-01-01T00:00:00Z"
    dry.preflight_path.write_text(json.dumps(payload), encoding="utf-8")
    dry.preflight_path.chmod(0o600)

    monkeypatch.setenv("SPRAY_DRY_RUN", "false")
    monkeypatch.setenv("SPRAY_PREFLIGHT", str(dry.preflight_path))
    with pytest.raises(ValueError, match="preflight expired"):
        prepare_run("oauth", config_binding={}, request_shape={})


def test_terminal_run_cannot_resume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _set_env(monkeypatch, tmp_path)
    dry = prepare_run("oauth", config_binding={}, request_shape={})
    monkeypatch.setenv("SPRAY_DRY_RUN", "false")
    monkeypatch.setenv("SPRAY_PREFLIGHT", str(dry.preflight_path))
    live = prepare_run("oauth", config_binding={}, request_shape={})
    finish_run(live, status="stopped", stop_reason="rate_limited", counters={}, exit_code=0)

    monkeypatch.setenv("SPRAY_PREFLIGHT", "")
    monkeypatch.setenv("SPRAY_RESUME", str(live.run_dir))
    with pytest.raises(ValueError, match="run is terminal"):
        prepare_run("oauth", config_binding={}, request_shape={})


def test_resume_rejects_corrupt_jsonl_and_concurrent_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _set_env(monkeypatch, tmp_path)
    dry = prepare_run("oauth", config_binding={}, request_shape={})
    monkeypatch.setenv("SPRAY_DRY_RUN", "false")
    monkeypatch.setenv("SPRAY_PREFLIGHT", str(dry.preflight_path))
    live = prepare_run("oauth", config_binding={}, request_shape={})
    finish_run(live, status="interrupted", stop_reason="sigint", counters={}, exit_code=130)

    monkeypatch.setenv("SPRAY_PREFLIGHT", "")
    monkeypatch.setenv("SPRAY_RESUME", str(live.run_dir))
    live.attempts_path.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid attempts JSONL"):
        prepare_run("oauth", config_binding={}, request_shape={})

    live.attempts_path.write_text("", encoding="utf-8")
    first = prepare_run("oauth", config_binding={}, request_shape={})
    try:
        with pytest.raises(ValueError, match="already active"):
            prepare_run("oauth", config_binding={}, request_shape={})
    finally:
        finish_run(first, status="interrupted", stop_reason="sigint", counters={}, exit_code=130)


def test_rejects_candidate_pool_insecure_password_file_and_secret_query(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _, passes = _set_env(monkeypatch, tmp_path)
    candidate = tmp_path / "candidate-pool.txt"
    candidate.write_text("Secret#1\n", encoding="utf-8")
    candidate.chmod(0o600)
    monkeypatch.setenv("SPRAY_PASSES_FILE", str(candidate))
    with pytest.raises(ValueError, match="cannot be used"):
        prepare_run("oauth", config_binding={}, request_shape={})

    monkeypatch.setenv("SPRAY_PASSES_FILE", str(passes))
    passes.chmod(0o644)
    with pytest.raises(ValueError, match="chmod 600"):
        prepare_run("oauth", config_binding={}, request_shape={})

    passes.chmod(0o600)
    monkeypatch.setenv("SPRAY_TARGET_URL", "https://login.example.test/token?access_token=secret")
    with pytest.raises(ValueError, match="secret-like query"):
        prepare_run("oauth", config_binding={}, request_shape={})

    monkeypatch.setenv("SPRAY_TARGET_URL", "https://login.example.test/token")
    shortlist = tmp_path / "spray-shortlist.txt"
    shortlist.write_text("Secret#1\n", encoding="utf-8")
    shortlist.chmod(0o600)
    monkeypatch.setenv("SPRAY_PASSES_FILE", str(shortlist))
    with pytest.raises(ValueError, match="companion metadata"):
        prepare_run("oauth", config_binding={}, request_shape={})

    metadata = tmp_path / "spray-shortlist.jsonl"
    invalid_metadata = {
        "schema_version": 1,
        "pwd_sha256_prefix": password_hash_prefix("Secret#1"),
        "source": "brand",
        "hibp_count": 0,
        "hibp_bucket": "zero",
        "reason": "selected Secret#1",
    }
    metadata.write_text(json.dumps(invalid_metadata) + "\n", encoding="utf-8")
    metadata.chmod(0o600)
    with pytest.raises(ValueError, match="plaintext password"):
        prepare_run("oauth", config_binding={}, request_shape={})

    metadata.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pwd_sha256_prefix": password_hash_prefix("Secret#1"),
                "source": "brand",
                "hibp_count": 0,
                "hibp_bucket": "zero",
                "reason": "target brand evidence",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    metadata.chmod(0o600)
    context = prepare_run("oauth", config_binding={}, request_shape={})
    assert context.binding["shortlist_meta_sha256"]
