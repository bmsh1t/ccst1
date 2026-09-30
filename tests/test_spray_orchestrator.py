"""Spray Shell 兼容入口的参数与 dry-run 回归。"""

from __future__ import annotations

import json
import os
import shutil
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
        env={**os.environ, "SPRAY_REPO_ROOT": str(tmp_path)},
    )

    assert completed.returncode == 0, completed.stderr
    assert "network attempts=0" in completed.stdout
    assert len(list(tmp_path.glob("recon/*/spray/preflight-*.json"))) == 1


def test_orchestrator_defaults_repo_root_to_script_checkout(tmp_path: Path):
    users, passes, spec = _inputs(tmp_path)
    checkout = tmp_path / "checkout"
    isolated_tools = checkout / "tools"
    isolated_tools.mkdir(parents=True)
    source_tools = Path(__file__).resolve().parents[1] / "tools"
    for name in ("spray_orchestrator.sh", "_spray_http_form.py", "spray_contract.py", "target_paths.py", "scope_context.py"):
        shutil.copy2(source_tools / name, isolated_tools / name)

    env = os.environ.copy()
    env.pop("SPRAY_REPO_ROOT", None)
    env.pop("SPRAY_PREFLIGHT_OUTPUT", None)
    completed = subprocess.run(
        [
            str(isolated_tools / "spray_orchestrator.sh"),
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
        env=env,
    )

    assert completed.returncode == 0, completed.stderr
    assert "network attempts=0" in completed.stdout
    assert len(list(checkout.glob("recon/*/spray/preflight-*.json"))) == 1
    assert not (tmp_path / "recon").exists()


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
        env={**os.environ, "SPRAY_REPO_ROOT": str(tmp_path)},
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
        env={**os.environ, "SPRAY_REPO_ROOT": str(tmp_path)},
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
        env={**os.environ, "SPRAY_REPO_ROOT": str(tmp_path)},
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
        env={**os.environ, "SPRAY_REPO_ROOT": str(tmp_path)},
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
        env={**os.environ, "SPRAY_REPO_ROOT": str(tmp_path)},
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
        env={**os.environ, "SPRAY_REPO_ROOT": str(tmp_path)},
    )
    assert completed.returncode == 1
    assert "--insecure is only valid" in completed.stderr


def test_internal_spray_shape_and_trevor_evidence_preserve_values(tmp_path, monkeypatch, capsys):
    import hashlib
    import io
    from types import SimpleNamespace
    from tools import _spray_trevor as trevor, spray_contract as contract

    users, passes, _ = _inputs(tmp_path)
    password = 'Secret"\\#1'
    passes.write_text(password + '\n')
    env = {
        'SPRAY_REPO_ROOT': str(tmp_path), 'SPRAY_TARGET_URL': 'http://127.0.0.1:9/login',
        'SPRAY_MODE': 'o365', 'SPRAY_USERS_FILE': str(users), 'SPRAY_PASSES_FILE': str(passes),
        'SPRAY_DELAY': '0', 'SPRAY_JITTER': '0', 'SPRAY_DRY_RUN': 'true',
        'SPRAY_PREFLIGHT': '', 'SPRAY_RESUME': '', 'SPRAY_PREFLIGHT_OUTPUT': '',
        'SPRAY_TREVOR_BIN': '/fixture/trevorspray',
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    shape = {'client_secret_set': True, 'nested': [{'password': password, 'session': False}],
             'headers': {'Authorization': 'Bearer synthetic-token'}}
    binding = {'fixture': 'exact'}
    preflight = contract.prepare_run('o365', config_binding=binding, request_shape=shape)
    saved = json.loads(preflight.preflight_path.read_text())
    assert saved['request_shape'] == shape
    assert preflight.preflight_path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setenv('SPRAY_DRY_RUN', 'false')
    monkeypatch.setenv('SPRAY_PREFLIGHT', str(preflight.preflight_path))
    context = contract.prepare_run('o365', config_binding=binding, request_shape=shape)
    manifest = json.loads((context.run_dir / 'run.json').read_text())
    assert manifest['request_shape'] == shape == context.shape
    assert manifest['binding'] == saved['binding'] == context.binding
    assert context.binding['passwords_sha256'] == hashlib.sha256((password + '\n').encode()).hexdigest()
    raw = json.dumps({'user': 'alice@example.test', 'password': password,
                      'access_token': 'synthetic-token', 'client_secret': 'synthetic-client'})
    stopped = []
    process = SimpleNamespace(stdout=io.StringIO(raw + '\n'), terminate=lambda: stopped.append(True),
                              wait=lambda: 0)
    monkeypatch.setattr(trevor, 'prepare_run', lambda *args, **kwargs: context)
    monkeypatch.setattr(trevor.subprocess, 'Popen', lambda *args, **kwargs: process)
    monkeypatch.setattr(trevor, 'finish_run', lambda *args, **kwargs: None)
    try:
        assert trevor.run() == 0
        assert raw in capsys.readouterr().out
        events = [json.loads(line) for line in context.attempts_path.read_text().splitlines()]
        assert len(events) == 1
        event = events[0]
        assert event['raw'] == raw
        assert event['classification'] == 'valid_token'
        assert event['attempt_key'] == context.attempt_key('alice@example.test', password)
        assert event['pwd_sha256_prefix'] == hashlib.sha256(password.encode()).hexdigest()[:12]
        assert stopped == [True]
        assert context.attempts_path.stat().st_mode & 0o777 == 0o600
        assert context.run_dir.stat().st_mode & 0o777 == 0o700
        assert (context.private_dir / 'trevor-inputs/passwords.txt').read_text() == password + '\n'
        assert (context.private_dir / 'trevor-inputs/passwords.txt').stat().st_mode & 0o777 == 0o600
    finally:
        contract._release_run_lock(context)


def test_spray_oauth_redirect_still_blocks_cross_target_credentials():
    import pytest
    from urllib.request import Request
    from tools._spray_oauth import ScopedRedirectHandler, ScopeRedirectError

    request = Request('https://target.test/token', data=b'password=synthetic-password',
                      headers={'Authorization': 'Bearer synthetic-token'})
    for status in (302, 307, 308):
        with pytest.raises(ScopeRedirectError, match='leaves target scope'):
            ScopedRedirectHandler('target.test').redirect_request(
                request, None, status, '', {}, 'https://other.test/token')
    assert request.data == b'password=synthetic-password'
    assert request.get_header('Authorization') == 'Bearer synthetic-token'
