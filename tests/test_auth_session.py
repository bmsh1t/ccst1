"""Offline regressions for selected auth sessions crossing environment boundaries."""

import argparse
import json
import os
import subprocess
from pathlib import Path

import pytest

from tools.auth_session import AuthSession, add_cli_args, session_from_args


def _polluted_env():
    return {
        "BBHUNT_AUTH_HEADERS": "Authorization: Bearer old-export\nX-Old: exported",
        "BBHUNT_SESSION_ID": "old-session",
        "BBHUNT_AUTH_TARGET": "https://old.test:8443",
        "BBHUNT_AUTH_ORIGINS": "https://stale.test:9443",
        "BBHUNT_AUTH_HEADER": "Authorization: Bearer old-header\nX-Old-Raw: raw",
        "BBHUNT_COOKIE": "sid=old",
        "BBHUNT_BEARER": "old-bearer",
        "BBHUNT_API_KEY": "old-key",
        "UNRELATED": "keep",
        "BBHUNT_AUTH_EXTRA": "keep-prefix-neighbor",
    }


@pytest.mark.parametrize("ambient", ["empty", "polluted", "malformed"])
@pytest.mark.parametrize(
    ("headers", "target", "origins"),
    [
        (["Authorization: Bearer selected"], "https://target.test:8443", []),
        (["Cookie: sid=selected", "X-API-Key: selected"], "https://target.test:8443",
         ["https://explicit.test:9443"]),
        (["Authorization: Bearer selected"], "", []),
        (["X-API-Key: selected"], "", ["https://explicit.test:9443"]),
        ([], "", []),
        ([], "https://target.test:8443", ["https://explicit.test:9443"]),
    ],
    ids=["bound", "explicit-origin", "unbound", "origin-only", "anonymous", "empty-bound"],
)
def test_export_roundtrip_replaces_all_auth_inputs(headers, target, origins, ambient):
    session = AuthSession(headers, target=target, allowed_origins=origins)
    before = (session.headers_list(), session.target(), session.allowed_origins(), session.env_overlay())
    env = {} if ambient == "empty" else _polluted_env()
    if ambient == "malformed":
        env.update({
            "BBHUNT_AUTH_HEADERS": "not-a-header",
            "BBHUNT_AUTH_HEADER": "also-invalid",
            "BBHUNT_AUTH_TARGET": "https://[broken",
            "BBHUNT_AUTH_ORIGINS": "https://[broken",
            "BBHUNT_COOKIE": "bad\rvalue",
            "BBHUNT_BEARER": "bad\rvalue",
            "BBHUNT_API_KEY": "bad\rvalue",
        })

    session.export_to_env(env)
    restored = AuthSession.from_env(env)

    unrelated = {} if ambient == "empty" else {
        "UNRELATED": "keep", "BBHUNT_AUTH_EXTRA": "keep-prefix-neighbor",
    }
    assert env == unrelated | before[3]
    assert restored.headers_list() == headers
    assert restored.session_id() == session.session_id()
    assert restored.target() == (before[1] if headers else "")
    assert restored.allowed_origins() == (origins if headers else [])
    if headers and target:
        assert env["BBHUNT_AUTH_TARGET"] == target
        assert restored.headers_for_url("https://target.test:8443/path") == session.headers_dict()
    if headers and origins:
        assert restored.headers_for_url("https://explicit.test:9443/path") == session.headers_dict()
    for denied in (
        "https://old.test:8443/path", "https://stale.test:9443/path",
        "http://target.test:8443/path", "https://target.test:9443/path",
        "http://explicit.test:9443/path", "https://explicit.test:8443/path",
        "", "not-a-url",
    ):
        assert restored.headers_for_url(denied) == {}
    if headers and not target and not origins:
        assert restored.headers_for_url("https://target.test:8443/path") == {}

    exported = env.copy()
    session.export_to_env(env)
    assert env == exported
    assert (session.headers_list(), session.target(), session.allowed_origins(), session.env_overlay()) == before


def test_default_export_clears_process_auth_environment(monkeypatch):
    for key, value in _polluted_env().items():
        monkeypatch.setenv(key, value)
    AuthSession().export_to_env()
    assert AuthSession.from_env().is_empty()
    for key in _polluted_env().keys() - {"UNRELATED", "BBHUNT_AUTH_EXTRA"}:
        assert key not in os.environ
    assert os.environ["UNRELATED"] == "keep"
    assert os.environ["BBHUNT_AUTH_EXTRA"] == "keep-prefix-neighbor"


@pytest.mark.parametrize("kind", ["bound", "anonymous", "unbound"])
@pytest.mark.parametrize("url", [
    "https://target.test:8443/path", "https://explicit.test:9443/path",
    "https://stale.test:9443/path", "https://old.test:8443/path",
])
def test_shell_helper_consumes_only_exported_session(kind, url):
    session = AuthSession(
        [] if kind == "anonymous" else ["Authorization: Bearer selected", "Cookie: sid=selected"],
        target="https://target.test:8443" if kind == "bound" else "",
        allowed_origins=["https://explicit.test:9443"] if kind == "bound" else [],
    )
    env = {"PATH": os.defpath, **_polluted_env()}
    session.export_to_env(env)
    helper = Path(__file__).resolve().parents[1] / "tools" / "_auth_helper.sh"
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", r'''
set -eu
source "$1"
bb_auth_args_for_url "$2"
printf '%s\0' "$BB_AUTH_SESSION_ID" "${BB_URL_AUTH_ARGS[@]}"
''', "auth-roundtrip", str(helper), url],
        env=env, capture_output=True, text=True, check=True, timeout=10,
    )
    assert result.stdout.split("\0")[:-1] == [session.session_id(), *session.curl_args_for_url(url)]


def test_initial_env_file_and_cli_sources_keep_existing_precedence(tmp_path):
    env = {
        "BBHUNT_AUTH_HEADER": "X-Raw: raw",
        "BBHUNT_COOKIE": "sid=raw",
        "BBHUNT_BEARER": "raw",
        "BBHUNT_API_KEY": "raw",
    }
    expected_raw = {"X-Raw": "raw", "Cookie": "sid=raw", "Authorization": "Bearer raw", "X-API-Key": "raw"}
    parser = argparse.ArgumentParser()
    add_cli_args(parser)
    assert session_from_args(parser.parse_args([]), env).headers_dict() == expected_raw

    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({"headers": ["X-File: file"], "bearer": "file"}), encoding="utf-8")
    file_args = ["--auth-file", str(auth_file)]
    assert session_from_args(parser.parse_args(file_args), env).headers_dict() == {
        "X-File": "file", "Authorization": "Bearer file",
    }
    cli_args = ["--auth-header", "X-Cli: cli", "--cookie", "sid=cli", "--bearer", "cli", "--api-key", "cli"]
    expected_cli = {"X-Cli": "cli", "Cookie": "sid=cli", "Authorization": "Bearer cli", "X-API-Key": "cli"}
    assert session_from_args(parser.parse_args(cli_args), env).headers_dict() == expected_cli
    assert session_from_args(
        parser.parse_args([*file_args, *cli_args, "--auth-from-env"]), env,
    ).headers_dict() == {"X-Raw": "raw", "X-File": "file", **expected_cli}


@pytest.mark.parametrize("conflict", ["environment", "cli-target"])
def test_source_target_mismatch_still_fails_before_export(tmp_path, conflict):
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({"target": "target.test", "bearer": "file"}), encoding="utf-8")
    env = {"BBHUNT_AUTH_TARGET": "other.test", "BBHUNT_BEARER": "raw"} if conflict == "environment" else {}
    before = env.copy()
    with pytest.raises(ValueError, match="auth source target mismatch"):
        AuthSession.from_sources(env=env, file=auth_file, target="other.test" if conflict == "cli-target" else "target.test")
    assert env == before
