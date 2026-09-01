"""Tests for tools/oast_listen.py — OAST callback listener."""

from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import oast_listen  # noqa: E402
from tools.action_queue import load_queue  # noqa: E402


@pytest.fixture
def isolated_findings(tmp_path, monkeypatch):
    """Redirect FINDINGS_ROOT to a tmp dir for test isolation."""
    monkeypatch.setattr(oast_listen, "FINDINGS_ROOT", tmp_path)
    monkeypatch.setattr(oast_listen, "REPO_ROOT", tmp_path)
    return tmp_path


# ─── Soft dependency ────────────────────────────────────────────────────────
def test_start_soft_dep_missing_interactsh_exits_zero(isolated_findings, capsys):
    """No interactsh-client + no --allow-external => exit 0 + hint."""
    with patch.object(oast_listen, "interactsh_installed", return_value=False):
        rc = oast_listen.main(["start", "--target", "demo.com"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "## CLAUDE_HINT" in captured.out
    assert "soft_dep_missing" in captured.out
    assert "interactsh-client not installed" in captured.err


def test_start_falls_back_to_webhook_site_with_allow_external(isolated_findings, capsys):
    """With --allow-external and no interactsh, webhook.site is invoked."""
    fake_response = MagicMock()
    fake_response.__enter__ = MagicMock(return_value=fake_response)
    fake_response.__exit__ = MagicMock(return_value=False)
    fake_response.read = MagicMock(return_value=json.dumps({"uuid": "fake-token-123"}).encode())
    with patch.object(oast_listen, "interactsh_installed", return_value=False), patch.object(
        oast_listen, "urlopen", return_value=fake_response
    ):
        rc = oast_listen.main(["start", "--target", "demo.com", "--allow-external"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "webhook.site/fake-token-123" in captured.out
    paths = oast_listen._paths("demo.com")
    assert paths["url"].read_text().strip().endswith("fake-token-123")
    assert paths["backend"].read_text().strip() == "webhook.site"
    assert paths["pid"].read_text().strip() == "0"
    queue = load_queue(isolated_findings, "demo.com")
    assert any(item["type"] == "oast-callback" for item in queue["actions"])


def test_start_emits_hint_on_already_running(isolated_findings, capsys):
    """Existing live pid => skip re-spawn, emit already_running hint."""
    paths = oast_listen._paths("demo.com")
    paths["base"].mkdir(parents=True)
    paths["pid"].write_text(str(os.getpid()))  # current process: definitely alive
    paths["url"].write_text("abc.oast.fun")
    with patch.object(oast_listen, "interactsh_installed", return_value=True), patch.object(
        oast_listen, "_pid_matches_oast", return_value=True
    ):
        rc = oast_listen.main(["start", "--target", "demo.com"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "already_running" in captured.out
    assert "abc.oast.fun" in captured.out


def test_legacy_start_provider_interactsh_uses_default_target(isolated_findings, capsys):
    """旧式 `--start --provider interactsh` 不应把 provider 值误当 subcommand。"""
    with patch.object(oast_listen, "interactsh_installed", return_value=False):
        rc = oast_listen.main(["--start", "--provider", "interactsh"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "state: soft_dep_missing" in captured.out
    assert "target: default" in captured.out


def test_legacy_start_provider_keeps_explicit_target(isolated_findings, capsys):
    """旧式 flag 带 target 时仍写入目标专属 OAST 状态。"""
    with patch.object(oast_listen, "interactsh_installed", return_value=False):
        rc = oast_listen.main([
            "--start",
            "--provider",
            "interactsh",
            "--target",
            "shop.example",
        ])
    captured = capsys.readouterr()
    assert rc == 0
    assert "target: shop.example" in captured.out


def test_legacy_start_provider_webhook_maps_allow_external(isolated_findings, capsys):
    """旧式 `--provider webhook.site` 等价于 start + --allow-external。"""
    fake_response = MagicMock()
    fake_response.__enter__ = MagicMock(return_value=fake_response)
    fake_response.__exit__ = MagicMock(return_value=False)
    fake_response.read = MagicMock(return_value=json.dumps({"uuid": "legacy-token"}).encode())
    with patch.object(oast_listen, "interactsh_installed", return_value=False), patch.object(
        oast_listen, "urlopen", return_value=fake_response
    ):
        rc = oast_listen.main([
            "--start",
            "--provider",
            "webhook.site",
            "--target",
            "demo.com",
        ])
    captured = capsys.readouterr()
    assert rc == 0
    assert "backend: webhook.site" in captured.out
    assert "webhook.site/legacy-token" in captured.out


def test_pid_alive_handles_dead_pid(isolated_findings):
    """A pid that was never spawned should report not alive."""
    # PID 999999 is exceedingly unlikely to exist.
    assert oast_listen._pid_alive(999999) is False


def test_stop_cleans_stale_live_pid_without_killing(isolated_findings, capsys):
    """pid 复用/撞到无关进程时，只清状态，不应对无关 pid 发 SIGTERM。"""
    paths = oast_listen._paths("demo.com")
    paths["base"].mkdir(parents=True)
    paths["pid"].write_text("3")
    paths["url"].write_text("abc.oast.fun")
    paths["backend"].write_text("interactsh")
    with patch.object(oast_listen, "_pid_alive", return_value=True), patch.object(
        oast_listen, "_pid_matches_oast", return_value=False
    ), patch.object(oast_listen.os, "kill") as mock_kill:
        rc = oast_listen.main(["stop", "--target", "demo.com"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "does not match this OAST listener" in captured.err
    mock_kill.assert_not_called()
    assert not paths["pid"].exists()


# ─── Poll ───────────────────────────────────────────────────────────────────
def test_poll_drains_interactsh_jsonl(isolated_findings, capsys):
    paths = oast_listen._paths("demo.com")
    paths["base"].mkdir(parents=True)
    paths["backend"].write_text("interactsh")
    oast_listen._sync_start_action(target="demo.com", backend="interactsh", url="abc.oast.fun", pid=4242)
    paths["callbacks"].write_text(
        json.dumps({
            "timestamp": "2026-05-13T08:30:00Z",
            "protocol": "dns",
            "remote-address": "1.2.3.4",
            "unique-id": "abc.oast.fun",
            "request": "abc.oast.fun. IN A",
            "raw-request": "...",
        }) + "\n"
        + json.dumps({
            "timestamp": "2026-05-13T08:31:00Z",
            "protocol": "http",
            "remote-address": "5.6.7.8",
            "unique-id": "abc.oast.fun",
            "request": "GET / HTTP/1.1",
            "raw-request": "...",
        }) + "\n"
    )
    rc = oast_listen.main(["poll", "--target", "demo.com", "--since-ts", "0"])
    captured = capsys.readouterr()
    assert rc == 0
    # Two normalized rows printed before the hint block.
    out_lines = [line for line in captured.out.splitlines() if line.startswith("{")]
    assert len(out_lines) == 2
    parsed = [json.loads(line) for line in out_lines]
    assert {r["protocol"] for r in parsed} == {"dns", "http"}
    assert "## CLAUDE_HINT" in captured.out
    assert "new_callbacks: 2" in captured.out
    queue = load_queue(isolated_findings, "demo.com")
    assert next(item for item in queue["actions"] if item["type"] == "oast-callback")["status"] == "candidate"


def test_poll_emits_hint_when_no_callbacks(isolated_findings, capsys):
    rc = oast_listen.main(["poll", "--target", "demo.com"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "new_callbacks: 0" in captured.out


def test_webhook_poll_persists_callback_and_returns_success(isolated_findings, capsys):
    paths = oast_listen._paths("demo.com")
    paths["base"].mkdir(parents=True)
    paths["backend"].write_text("webhook.site")
    paths["url"].write_text("https://webhook.site/token-123")
    oast_listen._sync_start_action(
        target="demo.com",
        backend="webhook.site",
        url="https://webhook.site/token-123",
    )
    fake_response = MagicMock()
    fake_response.__enter__ = MagicMock(return_value=fake_response)
    fake_response.__exit__ = MagicMock(return_value=False)
    fake_response.read = MagicMock(
        return_value=json.dumps(
            {"data": [{"created_at": "2026-05-13T08:30:00Z", "ip": "1.2.3.4", "url": "/cb", "method": "GET"}]}
        ).encode()
    )
    with patch.object(oast_listen, "urlopen", return_value=fake_response):
        assert oast_listen.main(["poll", "--target", "demo.com", "--since-ts", "0"]) == 0
    assert paths["callbacks"].is_file()
    queue = load_queue(isolated_findings, "demo.com")
    assert next(item for item in queue["actions"] if item["type"] == "oast-callback")["status"] == "candidate"


# ─── Stop ───────────────────────────────────────────────────────────────────
def test_stop_sends_sigterm_and_clears_state(isolated_findings, capsys):
    paths = oast_listen._paths("demo.com")
    paths["base"].mkdir(parents=True)
    paths["pid"].write_text("4242")
    paths["url"].write_text("abc.oast.fun")
    paths["backend"].write_text("interactsh")
    paths["callbacks"].write_text(json.dumps({"timestamp": "x"}) + "\n")

    kills = []

    def fake_kill(pid, sig):
        kills.append((pid, sig))
        # After SIGTERM we want _pid_alive to return False so SIGKILL is skipped.

    def fake_pid_alive(pid):
        # Before SIGTERM call returns True (1 check), then False.
        return len(kills) == 0

    with patch.object(oast_listen, "os") as mock_os, patch.object(
        oast_listen, "_pid_alive", side_effect=fake_pid_alive
    ):
        mock_os.getpgid.return_value = 4242
        mock_os.killpg.side_effect = fake_kill
        mock_os.kill = MagicMock()
        # signal module import is local in oast_listen — re-import via attribute.
        mock_os.SIGTERM = signal.SIGTERM
        mock_os.SIGKILL = signal.SIGKILL
        rc = oast_listen.main(["stop", "--target", "demo.com"])

    assert rc == 0
    assert (4242, signal.SIGTERM) in kills
    mock_os.kill.assert_not_called()
    assert not paths["pid"].is_file()
    assert not paths["url"].is_file()
    # callbacks.jsonl must be preserved across stop for post-mortem analysis.
    assert paths["callbacks"].is_file()


def test_stop_handles_webhook_site_pid_zero(isolated_findings, capsys):
    paths = oast_listen._paths("demo.com")
    paths["base"].mkdir(parents=True)
    paths["pid"].write_text("0")
    paths["url"].write_text("https://webhook.site/abc")
    paths["backend"].write_text("webhook.site")
    paths["callbacks"].write_text("{}\n")
    rc = oast_listen.main(["stop", "--target", "demo.com"])
    assert rc == 0
    assert not paths["pid"].is_file()
    assert not paths["url"].is_file()
    assert not paths["backend"].is_file()
    assert paths["callbacks"].is_file()


def test_stop_warns_when_nothing_running(isolated_findings, capsys):
    rc = oast_listen.main(["stop", "--target", "demo.com"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "no OAST instance recorded" in captured.err


def test_stop_without_callbacks_closes_active_queue_action(isolated_findings, capsys):
    paths = oast_listen._paths("demo.com")
    paths["base"].mkdir(parents=True)
    paths["pid"].write_text("0")
    paths["url"].write_text("https://webhook.site/abc")
    paths["backend"].write_text("webhook.site")
    oast_listen._sync_start_action(target="demo.com", backend="webhook.site", url="https://webhook.site/abc")

    assert oast_listen.main(["stop", "--target", "demo.com"]) == 0
    queue = load_queue(isolated_findings, "demo.com")
    action = next(item for item in queue["actions"] if item["type"] == "oast-callback")
    assert action["status"] == "dead-end"


# ─── Status ─────────────────────────────────────────────────────────────────
def test_status_lists_all_targets(isolated_findings, capsys):
    for target in ("a.com", "b.com"):
        paths = oast_listen._paths(target)
        paths["base"].mkdir(parents=True)
        paths["pid"].write_text("0")
        paths["url"].write_text(f"https://webhook.site/{target}-tok")
        paths["backend"].write_text("webhook.site")
    rc = oast_listen.main(["status"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "a.com" in captured.out
    assert "b.com" in captured.out
    assert "webhook.site" in captured.out


def test_status_with_no_instances(isolated_findings, capsys):
    rc = oast_listen.main(["status"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "no OAST instances" in captured.out


def test_cleanup_reuses_stop_for_recorded_targets(isolated_findings, monkeypatch, capsys):
    for target in ("live.example", "stale.example"):
        paths = oast_listen._paths(target)
        paths["base"].mkdir(parents=True)
        paths["pid"].write_text("1234")
    (isolated_findings / "not-oast").mkdir()
    stopped = []
    monkeypatch.setattr(oast_listen, "cmd_stop", lambda target: stopped.append(target) or 0)

    assert oast_listen.main(["cleanup"]) == 0

    assert stopped == ["live.example", "stale.example"]
    assert "checked 2 recorded listener(s)" in capsys.readouterr().err


# ─── Normalization helper ───────────────────────────────────────────────────
def test_iso_to_unix_handles_z_suffix():
    ts = oast_listen._iso_to_unix("2026-05-13T08:30:00Z")
    assert ts > 0


def test_iso_to_unix_handles_empty():
    assert oast_listen._iso_to_unix("") == 0
