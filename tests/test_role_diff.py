"""Tests for tools/role_diff.py — multi-role endpoint diff."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import role_diff  # noqa: E402  (tools/role_diff.py)


# ─── Session parsing ────────────────────────────────────────────────────────
def test_parse_session_no_auth_keyword():
    role, sess = role_diff.parse_session_arg("no_auth=NONE")
    assert role == "no_auth"
    assert sess == {"headers": {}}


def test_parse_session_cookie_only(tmp_path):
    path = tmp_path / "a.json"
    path.write_text(json.dumps({"cookie": "session=abc"}))
    role, sess = role_diff.parse_session_arg(f"user_a={path}")
    assert role == "user_a"
    assert sess["headers"]["Cookie"] == "session=abc"


def test_parse_session_bearer_only(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"bearer": "eyJtoken"}))
    _, sess = role_diff.parse_session_arg(f"user_b={path}")
    assert sess["headers"]["Authorization"] == "Bearer eyJtoken"


def test_parse_session_headers_merge(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({
        "headers": {"X-Tenant": "demo"},
        "cookie": "s=1",
        "bearer": "tok",
        "api_key": "key123",
    }))
    _, sess = role_diff.parse_session_arg(f"admin={path}")
    headers = sess["headers"]
    assert headers["X-Tenant"] == "demo"
    assert headers["Cookie"] == "s=1"
    assert headers["Authorization"] == "Bearer tok"
    assert headers["X-API-Key"] == "key123"


def test_parse_session_rejects_missing_equals():
    with pytest.raises(ValueError):
        role_diff.parse_session_arg("only_role")


def test_parse_session_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        role_diff.parse_session_arg(f"user_x={tmp_path / 'nope.json'}")


def test_parse_sessions_rejects_duplicate(tmp_path):
    path = tmp_path / "z.json"
    path.write_text(json.dumps({}))
    with pytest.raises(ValueError):
        role_diff.parse_sessions(
            [f"user_a={path}", f"user_a={path}"]
        )


# ─── Endpoint parsing ───────────────────────────────────────────────────────
def test_parse_endpoints_default_get(tmp_path):
    f = tmp_path / "e.txt"
    f.write_text(
        "https://t.com/api/users/1\n"
        "# comment line\n"
        "\n"
        "GET https://t.com/api/users/2\n"
    )
    eps = role_diff.parse_endpoints_file(f, {"GET"})
    assert eps == [
        ("GET", "https://t.com/api/users/1"),
        ("GET", "https://t.com/api/users/2"),
    ]


def test_parse_endpoints_rejects_disallowed_method(tmp_path):
    f = tmp_path / "e.txt"
    f.write_text("DELETE https://t.com/api/users/1\n")
    with pytest.raises(ValueError, match="DELETE"):
        role_diff.parse_endpoints_file(f, {"GET"})


def test_parse_endpoints_rejects_non_absolute(tmp_path):
    f = tmp_path / "e.txt"
    f.write_text("/api/users/1\n")
    with pytest.raises(ValueError, match="absolute"):
        role_diff.parse_endpoints_file(f, {"GET"})


# ─── Signal detection ───────────────────────────────────────────────────────
def _by_role(rows):
    """Helper: build by_role dict from list of (role, status, size, hash) tuples."""
    out = {}
    for role, status, size, body_hash in rows:
        out[role] = {
            "status": status, "size": size, "hash": body_hash,
            "latency_ms": 100, "error": None,
        }
    return out


def test_signal_status_diff():
    by_role = _by_role([
        ("user_a", 200, 1000, "aaaa"),
        ("user_b", 403, 56, "bbbb"),
    ])
    sigs = role_diff.detect_signals(by_role, diff_size_pct=30)
    assert "status_diff" in sigs


def test_signal_size_diff_within_same_class():
    by_role = _by_role([
        ("user_a", 200, 1000, "aaaa"),
        ("user_b", 200, 300, "bbbb"),
    ])
    sigs = role_diff.detect_signals(by_role, diff_size_pct=30)
    assert "size_diff" in sigs
    assert "status_diff" not in sigs


def test_signal_hash_match_strong_idor():
    """Two different roles returning byte-identical bodies — strong IDOR signal."""
    same_hash = "deadbeefdeadbeef"
    by_role = _by_role([
        ("user_a", 200, 1234, same_hash),
        ("user_b", 200, 1234, same_hash),
    ])
    sigs = role_diff.detect_signals(by_role, diff_size_pct=30)
    assert "hash_match" in sigs


def test_signal_leak_to_unauth():
    by_role = _by_role([
        ("user_a", 200, 1500, "aaaa"),
        ("no_auth", 200, 1200, "bbbb"),
    ])
    sigs = role_diff.detect_signals(by_role, diff_size_pct=30)
    assert "leak_to_unauth" in sigs


def test_signal_no_signal_when_consistent():
    by_role = _by_role([
        ("user_a", 200, 1000, "aaaa"),
        ("user_b", 200, 1000, "bbbb"),  # different content (different hash), same size
    ])
    sigs = role_diff.detect_signals(by_role, diff_size_pct=30)
    assert sigs == []


# ─── End-to-end with mocked HTTP ────────────────────────────────────────────
def test_run_role_diff_writes_result_json(tmp_path):
    endpoints = [("GET", "https://t.com/api/users/123")]
    sessions = {
        "user_a": {"headers": {"Authorization": "Bearer A"}},
        "user_b": {"headers": {"Authorization": "Bearer B"}},
    }

    # Mock _do_request to return identical hashes (hash_match scenario).
    def fake_request(method, url, headers, timeout):
        return {
            "status": 200, "size": 1234, "hash": "samesame",
            "latency_ms": 50, "error": None,
        }

    with patch.object(role_diff, "_do_request", side_effect=fake_request):
        result = role_diff.run_role_diff(
            target="t.com",
            endpoints=endpoints,
            sessions=sessions,
            out_dir=tmp_path,
        )

    assert (tmp_path / "result.json").is_file()
    on_disk = json.loads((tmp_path / "result.json").read_text())
    assert on_disk["target"] == "t.com"
    assert on_disk["summary"]["hash_match_count"] == 1
    assert on_disk["summary"]["high_signal_count"] == 1
    # Roles preserved in order.
    assert on_disk["roles"] == ["user_a", "user_b"]


def test_main_emit_claude_hint_in_stdout(tmp_path, capsys):
    eps = tmp_path / "endpoints.txt"
    eps.write_text("https://t.com/api/users/1\n")
    sess = tmp_path / "a.json"
    sess.write_text(json.dumps({"cookie": "s=1"}))

    def fake_request(method, url, headers, timeout):
        return {
            "status": 200, "size": 100, "hash": "h",
            "latency_ms": 50, "error": None,
        }

    with patch.object(role_diff, "_do_request", side_effect=fake_request):
        rc = role_diff.main(
            [
                "--target", "t.com",
                "--endpoints", str(eps),
                "--session", f"user_a={sess}",
                "--session", "no_auth=NONE",
                "--out-dir", str(tmp_path / "out"),
            ]
        )

    captured = capsys.readouterr()
    assert rc == 0
    assert "## CLAUDE_HINT" in captured.out
    assert "phase: role_diff" in captured.out
    assert "next_priority_action" in captured.out


def test_terminal_summary_does_not_leak_session_content(tmp_path, capsys):
    """Sessions must never be echoed to stdout (Cookie/Bearer never visible)."""
    eps = tmp_path / "endpoints.txt"
    eps.write_text("https://t.com/api/users/1\n")
    sess = tmp_path / "secret.json"
    sess.write_text(json.dumps({
        "cookie": "session=SUPER_SECRET_TOKEN_xyz",
        "bearer": "eyJBEARER_LEAK_alphabeta",
    }))

    def fake_request(method, url, headers, timeout):
        return {
            "status": 200, "size": 0, "hash": "",
            "latency_ms": 10, "error": None,
        }

    with patch.object(role_diff, "_do_request", side_effect=fake_request):
        role_diff.main(
            [
                "--target", "t.com",
                "--endpoints", str(eps),
                "--session", f"admin={sess}",
                "--out-dir", str(tmp_path / "out"),
            ]
        )

    captured = capsys.readouterr()
    assert "SUPER_SECRET_TOKEN_xyz" not in captured.out
    assert "SUPER_SECRET_TOKEN_xyz" not in captured.err
    assert "eyJBEARER_LEAK_alphabeta" not in captured.out
    assert "eyJBEARER_LEAK_alphabeta" not in captured.err


def test_main_rejects_missing_session(tmp_path):
    eps = tmp_path / "endpoints.txt"
    eps.write_text("https://t.com/api/users/1\n")
    rc = role_diff.main([
        "--target", "t.com",
        "--endpoints", str(eps),
    ])
    assert rc == 2
