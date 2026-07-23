"""TREVORspray emitted-event JSONL 与身份结果分类回归。"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tools import _spray_trevor as trevor


@pytest.mark.parametrize(
    ("code", "classification", "credential_valid"),
    [
        ("50034", "invalid_user", False),
        ("50126", "invalid_password", False),
        ("50053", "locked", None),
        ("53003", "valid_password_conditional_access", True),
        ("50076", "valid_password_mfa", True),
        ("50079", "valid_password_mfa", True),
        ("50158", "valid_password_external_auth", True),
        ("530003", "valid_password_device_required", True),
        ("65001", "consent_required", True),
        ("700016", "app_not_in_tenant", None),
        ("90002", "tenant_not_found", None),
    ],
)
def test_classify_aadsts_table(code: str, classification: str, credential_valid: bool | None):
    result = trevor.classify_emitted_line(
        f'{{"error":"invalid_grant","error_description":"AADSTS{code}: detail"}}',
        mode="o365",
    )

    assert result["aadsts_code"] == code
    assert result["classification"] == classification
    assert result["credential_valid"] is credential_valid
    assert result["token_issued"] is False


def test_top_level_access_token_is_required_for_token_issued():
    top_level = trevor.classify_emitted_line(
        '{"access_token":"TOKEN","claims":{"access_token":"nested"}}',
        mode="o365",
    )
    nested = trevor.classify_emitted_line(
        '{"error_description":"AADSTS50076","claims":{"access_token":"nested"}}',
        mode="o365",
    )
    plain_text = trevor.classify_emitted_line(
        'AADSTS50076 claims={"access_token":"nested"}',
        mode="o365",
    )
    claims_only = trevor.classify_emitted_line(
        'claims={"access_token":"nested"}',
        mode="o365",
    )

    assert top_level["classification"] == "valid_token"
    assert top_level["credential_valid"] is True
    assert top_level["token_issued"] is True
    assert nested["classification"] == "valid_password_mfa"
    assert nested["token_issued"] is False
    assert plain_text["classification"] == "valid_password_mfa"
    assert plain_text["token_issued"] is False
    assert claims_only["classification"] == "unknown"
    assert claims_only["token_issued"] is False


@pytest.mark.parametrize(
    ("payload", "classification", "credential_valid"),
    [
        ('{"errorCode":"E0000004"}', "invalid_credentials", False),
        ('{"errorCode":"E0000119"}', "locked", None),
        ('{"status":"LOCKED_OUT"}', "locked", None),
        ('{"status":"MFA_REQUIRED"}', "valid_password_mfa", True),
        ('{"status":"PASSWORD_EXPIRED"}', "valid_password_expired", True),
        ('{"status":"SUCCESS","sessionToken":"SESSION"}', "valid_session", True),
        ('{"errorCode":"E0000047"}', "rate_limited", None),
        ('HTTP 429 Too Many Requests', "rate_limited", None),
    ],
)
def test_classify_okta_table(payload: str, classification: str, credential_valid: bool | None):
    result = trevor.classify_emitted_line(payload, mode="okta")

    assert result["classification"] == classification
    assert result["credential_valid"] is credential_valid


def test_unknown_output_remains_unknown():
    result = trevor.classify_emitted_line("worker heartbeat", mode="o365")

    assert result["classification"] == "unknown"
    assert result["credential_valid"] is None
    assert result["token_issued"] is False


def test_redaction_removes_password_and_structured_tokens():
    line = (
        '{"password":"Secret#1","access_token":"ACCESS","sessionToken":"SESSION",'
        '"authorization":"Basic TOKEN.VALUE"} '
        "{'id_token': 'IDTOKEN'} refresh_token=REFRESH"
    )

    redacted = trevor.redact_passwords(line, ("Secret#1",))

    assert "Secret#1" not in redacted
    assert "ACCESS" not in redacted
    assert "SESSION" not in redacted
    assert "TOKEN.VALUE" not in redacted
    assert "IDTOKEN" not in redacted
    assert "REFRESH" not in redacted
    assert redacted.count("[REDACTED_SECRET]") == 5


def _write_fake_trevor(path: Path, *, exit_code: int = 0, valid: bool = True) -> None:
    aadsts = "50076" if valid else "50126"
    path.write_text(
        "\n".join(
            [
                f"#!{sys.executable}",
                "import json",
                "from pathlib import Path",
                "history = Path.home() / '.trevorspray' / 'tried_logins.txt'",
                "history.parent.mkdir(parents=True, exist_ok=True)",
                "history.write_text('alice@example.test:Secret#1')",
                f"print(json.dumps({{'user': 'alice@example.test', 'password': 'Secret#1', 'error_description': 'AADSTS{aadsts}: detail'}}), flush=True)",
                "print(json.dumps({'claims': {'access_token': 'nested-only'}}), flush=True)",
                f"raise SystemExit({exit_code})",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _adapter_env(tmp_path: Path, fake_trevor: Path) -> tuple[dict[str, str], Path]:
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    audit_root = tmp_path / "recon" / "login.example.test" / "spray"
    users.write_text("alice@example.test\nalice@example.test\n", encoding="utf-8")
    passes.write_text("Secret#1\nSecret#1\n", encoding="utf-8")
    passes.chmod(0o600)
    env = os.environ.copy()
    env.update(
        {
            "SPRAY_MODE": "o365",
            "SPRAY_TARGET_URL": "https://login.example.test",
            "SPRAY_USERS_FILE": str(users),
            "SPRAY_PASSES_FILE": str(passes),
            "SPRAY_DELAY": "1800",
            "SPRAY_JITTER": "60",
            "SPRAY_CONTINUE_ON_HIT": "false",
            "SPRAY_TREVOR_BIN": str(fake_trevor),
            "SPRAY_REPO_ROOT": str(tmp_path),
            "SPRAY_INTERACTIVE_CONFIRMED": "true",
        }
    )
    return env, audit_root


@pytest.mark.parametrize(("mode", "module"), [("o365", "msol"), ("okta", "okta")])
def test_build_command_matches_current_trevor_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    module: str,
):
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    users.write_text("alice@example.test\nbob@example.test\n", encoding="utf-8")
    passes.write_text("Secret#1\n", encoding="utf-8")
    env = {
        "SPRAY_TREVOR_BIN": "/root/.local/bin/trevorspray",
        "SPRAY_USERS_FILE": str(users),
        "SPRAY_PASSES_FILE": str(passes),
        "SPRAY_TARGET_URL": "https://login.example.test",
        "SPRAY_DELAY": "1800",
        "SPRAY_JITTER": "60",
        "SPRAY_CONTINUE_ON_HIT": "false",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    command = trevor._build_command(mode)

    assert command == [
        "/root/.local/bin/trevorspray",
        "--module",
        module,
        "--users",
        str(users),
        "--passwords",
        str(passes),
        "--url",
        "https://login.example.test",
        "--delay",
        "900",
        "--jitter",
        "30",
        "--no-loot",
        "--exit-on-success",
    ]


def test_build_command_continues_without_enabling_loot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    users = tmp_path / "users.txt"
    passes = tmp_path / "passes.txt"
    users.write_text("alice@example.test\n", encoding="utf-8")
    passes.write_text("Secret#1\n", encoding="utf-8")
    monkeypatch.setenv("SPRAY_TREVOR_BIN", "/root/.local/bin/trevorspray")
    monkeypatch.setenv("SPRAY_USERS_FILE", str(users))
    monkeypatch.setenv("SPRAY_PASSES_FILE", str(passes))
    monkeypatch.setenv("SPRAY_TARGET_URL", "https://login.example.test")
    monkeypatch.setenv("SPRAY_DELAY", "1800")
    monkeypatch.setenv("SPRAY_JITTER", "60")
    monkeypatch.setenv("SPRAY_CONTINUE_ON_HIT", "true")

    command = trevor._build_command("o365")

    assert command[command.index("--delay") + 1] == "1800"
    assert command[command.index("--jitter") + 1] == "60"
    assert "--no-loot" in command
    assert "--exit-on-success" not in command


def test_build_command_rejects_empty_users_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    users = tmp_path / "users.txt"
    users.write_text("\n", encoding="utf-8")
    monkeypatch.setenv("SPRAY_USERS_FILE", str(users))
    monkeypatch.setenv("SPRAY_DELAY", "1800")
    monkeypatch.setenv("SPRAY_JITTER", "60")

    with pytest.raises(ValueError, match="contains no usernames"):
        trevor._build_command("o365")


def test_adapter_writes_redacted_valid_jsonl_and_streams_redacted_output(tmp_path: Path):
    fake_trevor = tmp_path / "trevorspray"
    _write_fake_trevor(fake_trevor)
    env, audit_root = _adapter_env(tmp_path, fake_trevor)

    completed = subprocess.run(
        [sys.executable, str(Path(trevor.__file__))],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    audit = next(audit_root.glob("*/attempts.jsonl"))
    assert "Secret#1" not in completed.stdout
    assert "[REDACTED_PASSWORD]" in completed.stdout
    rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert all(row["schema_version"] == 1 for row in rows)
    assert all(row["event"] == "attempt_result" for row in rows)
    assert rows[0]["user"] == "alice@example.test"
    assert rows[0]["classification"] == "valid_password_mfa"
    assert rows[0]["pwd_sha256_prefix"]
    assert rows[0]["token_issued"] is False
    assert "Secret#1" not in audit.read_text(encoding="utf-8")
    isolated_history = next(
        tmp_path.glob(".private/spray/login.example.test/*/trevor-home/.trevorspray/tried_logins.txt")
    )
    assert "Secret#1" in isolated_history.read_text(encoding="utf-8")
    assert stat.S_IMODE(isolated_history.parents[1].stat().st_mode) == 0o700
    normalized_users = next(tmp_path.glob(".private/spray/login.example.test/*/trevor-inputs/users.txt"))
    normalized_passwords = next(
        tmp_path.glob(".private/spray/login.example.test/*/trevor-inputs/passwords.txt")
    )
    assert normalized_users.read_text(encoding="utf-8") == "alice@example.test\n"
    assert normalized_passwords.read_text(encoding="utf-8") == "Secret#1\n"


def test_adapter_preserves_nonzero_exit_and_records_error_summary(tmp_path: Path):
    fake_trevor = tmp_path / "trevorspray"
    _write_fake_trevor(fake_trevor, exit_code=7, valid=False)
    env, audit_root = _adapter_env(tmp_path, fake_trevor)

    completed = subprocess.run(
        [sys.executable, str(Path(trevor.__file__))],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 7
    audit = next(audit_root.glob("*/attempts.jsonl"))
    rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["event"] == "attempt_result"
    summaries = list(tmp_path.glob("recon/login.example.test/spray/*/summary.json"))
    assert len(summaries) == 1
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    assert summary["status"] == "error"
    assert summary["stop_reason"] == "tool_error"
    assert summary["exit_code"] == 7


def test_orchestrator_routes_trevor_modes_through_adapter():
    root = Path(__file__).resolve().parents[1]
    script = (root / "tools" / "spray_orchestrator.sh").read_text(encoding="utf-8")

    assert 'export SPRAY_MODE="$MODE"' in script
    assert 'export SPRAY_TREVOR_BIN="$TREVOR_BIN"' in script
    assert 'python3 "$SCRIPT_DIR/_spray_trevor.py"' in script
    assert 'tee -a "$AUDIT_LOG"' not in script
