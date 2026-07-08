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


@pytest.fixture
def isolated_findings(tmp_path, monkeypatch):
    """Redirect FINDINGS_ROOT to a tmp dir for test isolation."""
    monkeypatch.setattr(oast_listen, "FINDINGS_ROOT", tmp_path)
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
    out_lines = [l for l in captured.out.splitlines() if l.startswith("{")]
    assert len(out_lines) == 2
    parsed = [json.loads(l) for l in out_lines]
    assert {r["protocol"] for r in parsed} == {"dns", "http"}
    assert "## CLAUDE_HINT" in captured.out
    assert "new_callbacks: 2" in captured.out


def test_poll_emits_hint_when_no_callbacks(isolated_findings, capsys):
    rc = oast_listen.main(["poll", "--target", "demo.com"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "new_callbacks: 0" in captured.out


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
        mock_os.kill = fake_kill
        # signal module import is local in oast_listen — re-import via attribute.
        mock_os.SIGTERM = signal.SIGTERM
        mock_os.SIGKILL = signal.SIGKILL
        rc = oast_listen.main(["stop", "--target", "demo.com"])

    assert rc == 0
    assert (4242, signal.SIGTERM) in kills
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


# ─── Normalization helper ───────────────────────────────────────────────────
def test_iso_to_unix_handles_z_suffix():
    ts = oast_listen._iso_to_unix("2026-05-13T08:30:00Z")
    assert ts > 0


def test_iso_to_unix_handles_empty():
    assert oast_listen._iso_to_unix("") == 0


# ─── Payloads subcommand (PR-18) ────────────────────────────────────────────
class TestResolveVulnClass:
    """Case-insensitive vuln-class lookup — operator should not have to
    remember the exact casing of `SQLi` vs `SQLI` vs `sqli`."""

    def test_canonical_form(self):
        assert oast_listen._resolve_vuln_class("SQLi") == "SQLi"
        assert oast_listen._resolve_vuln_class("XXE") == "XXE"
        assert oast_listen._resolve_vuln_class("RCE") == "RCE"
        assert oast_listen._resolve_vuln_class("SSRF") == "SSRF"

    def test_lowercase(self):
        assert oast_listen._resolve_vuln_class("sqli") == "SQLi"
        assert oast_listen._resolve_vuln_class("xxe") == "XXE"
        assert oast_listen._resolve_vuln_class("rce") == "RCE"
        assert oast_listen._resolve_vuln_class("ssrf") == "SSRF"

    def test_uppercase(self):
        assert oast_listen._resolve_vuln_class("SQLI") == "SQLi"

    def test_with_whitespace(self):
        assert oast_listen._resolve_vuln_class("  XXE  ") == "XXE"

    def test_unknown_returns_none(self):
        assert oast_listen._resolve_vuln_class("LFI") is None
        assert oast_listen._resolve_vuln_class("CSRF") is None
        assert oast_listen._resolve_vuln_class("") is None


class TestPayloadTemplates:
    """Curation invariants for the OAST_PAYLOAD_TEMPLATES dict.

    Adding a new vuln class or payload row should preserve these invariants;
    if a check fails, fix the template list rather than the test."""

    REQUIRED_CLASSES = {"SSRF", "XXE", "RCE", "SQLi"}

    def test_all_required_classes_present(self):
        assert set(oast_listen.OAST_PAYLOAD_TEMPLATES) >= self.REQUIRED_CLASSES

    @pytest.mark.parametrize("vuln_class", ["SSRF", "XXE", "RCE", "SQLi"])
    def test_class_has_5_to_15_payloads(self, vuln_class):
        """PRD R6: curated, not exhaustive — quality over quantity."""
        templates = oast_listen.OAST_PAYLOAD_TEMPLATES[vuln_class]
        assert 5 <= len(templates) <= 15, (
            f"{vuln_class} has {len(templates)} payloads; PRD R6 requires 5-15"
        )

    @pytest.mark.parametrize("vuln_class", ["SSRF", "XXE", "RCE", "SQLi"])
    def test_every_payload_uses_oast_url_token(self, vuln_class):
        """Every template must reference OAST_URL — otherwise it can't carry
        the callback and is dead weight in a blind-class kit."""
        templates = oast_listen.OAST_PAYLOAD_TEMPLATES[vuln_class]
        for i, template in enumerate(templates):
            assert "OAST_URL" in template, (
                f"{vuln_class}[{i}] missing OAST_URL token: {template[:80]!r}"
            )


class TestCmdPayloadsErrors:
    """AC2: errors gracefully when no listener was started for the target."""

    def test_no_url_file_returns_nonzero_with_clear_message(
        self, isolated_findings, capsys
    ):
        """AC2: clear error, exit != 0, no traceback."""
        rc = oast_listen.main(["payloads", "--target", "ghost.com",
                               "--vuln-class", "XXE"])
        captured = capsys.readouterr()
        assert rc != 0
        assert "no OAST URL recorded for ghost.com" in captured.err
        assert "Run `python3 tools/oast_listen.py start" in captured.err
        # No payloads should leak to stdout when listener is missing
        assert "<!DOCTYPE" not in captured.out
        assert "OAST_URL" not in captured.out

    def test_empty_url_file_returns_nonzero(self, isolated_findings, capsys):
        """A url.txt that exists but is empty is also a failure mode —
        usually means the listener started but never registered a callback."""
        paths = oast_listen._paths("ghost.com")
        paths["base"].mkdir(parents=True)
        paths["url"].write_text("   \n")
        rc = oast_listen.main(["payloads", "--target", "ghost.com",
                               "--vuln-class", "XXE"])
        captured = capsys.readouterr()
        assert rc != 0
        assert "empty" in captured.err.lower()

    def test_unknown_vuln_class_returns_nonzero(self, isolated_findings, capsys):
        """argparse choices catches most cases, but the function-level guard
        also rejects unknown classes when called directly (e.g. from autopilot)."""
        paths = oast_listen._paths("demo.com")
        paths["base"].mkdir(parents=True)
        paths["url"].write_text("abc.oast.fun")
        rc = oast_listen.cmd_payloads("demo.com", "Path")  # not in dict
        captured = capsys.readouterr()
        assert rc != 0
        assert "unknown vuln-class" in captured.err
        assert "Path" in captured.err


class TestCmdPayloadsSubstitution:
    """AC3 + AC4: literal substitution and per-class non-empty output."""

    def test_substitutes_fixture_url_literally(self, isolated_findings, capsys):
        """AC3: url.txt contains `https://abc.oast.fun`; output payloads must
        contain that literal string and zero `OAST_URL` placeholder remnants."""
        paths = oast_listen._paths("demo.com")
        paths["base"].mkdir(parents=True)
        paths["url"].write_text("https://abc.oast.fun")
        rc = oast_listen.main(["payloads", "--target", "demo.com",
                               "--vuln-class", "XXE"])
        captured = capsys.readouterr()
        assert rc == 0
        # The literal URL must appear in stdout
        assert "https://abc.oast.fun" in captured.out
        # The placeholder must not survive substitution
        # (We split out the CLAUDE_HINT block which legitimately echoes the URL
        #  without the placeholder, so a single global check is fine.)
        payload_section = captured.out.split("## CLAUDE_HINT")[0]
        assert "OAST_URL" not in payload_section

    @pytest.mark.parametrize("vuln_class", ["SSRF", "XXE", "RCE", "SQLi"])
    def test_each_class_produces_nonempty_output(
        self, vuln_class, isolated_findings, capsys
    ):
        """AC4: every supported class produces at least one substituted
        payload when invoked end-to-end."""
        paths = oast_listen._paths("demo.com")
        paths["base"].mkdir(parents=True)
        paths["url"].write_text("abc.oast.fun")
        rc = oast_listen.main(["payloads", "--target", "demo.com",
                               "--vuln-class", vuln_class])
        captured = capsys.readouterr()
        assert rc == 0
        payload_section = captured.out.split("## CLAUDE_HINT")[0]
        # Strip the `---` separators and blank lines, expect ≥1 payload row
        rows = [
            line for line in payload_section.splitlines()
            if line.strip() and line.strip() != "---"
        ]
        assert len(rows) >= 1, f"{vuln_class}: no payload rows in stdout"
        assert "abc.oast.fun" in captured.out

    def test_writes_payloads_file_for_replay(self, isolated_findings, capsys):
        """Persisted file lets the operator replay or paste-from-disk later
        instead of re-running the command."""
        paths = oast_listen._paths("demo.com")
        paths["base"].mkdir(parents=True)
        paths["url"].write_text("abc.oast.fun")
        rc = oast_listen.main(["payloads", "--target", "demo.com",
                               "--vuln-class", "SSRF"])
        assert rc == 0
        out_file = paths["base"] / "payloads_SSRF.txt"
        assert out_file.is_file()
        content = out_file.read_text(encoding="utf-8")
        assert "abc.oast.fun" in content
        assert "OAST_URL" not in content

    def test_emits_claude_hint_block(self, isolated_findings, capsys):
        """The CLAUDE_HINT block must be emitted so autopilot/Claude can grep
        for state without statting individual files."""
        paths = oast_listen._paths("demo.com")
        paths["base"].mkdir(parents=True)
        paths["url"].write_text("abc.oast.fun")
        rc = oast_listen.main(["payloads", "--target", "demo.com",
                               "--vuln-class", "RCE"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "## CLAUDE_HINT" in captured.out
        assert "phase: oast_payloads" in captured.out
        assert "vuln_class: RCE" in captured.out
        assert "oast_url: abc.oast.fun" in captured.out
        assert "payload_count:" in captured.out

    def test_case_insensitive_cli(self, isolated_findings, capsys):
        """argparse's `choices=` uses sorted canonical keys; calling the
        function directly with mixed casing must still resolve."""
        paths = oast_listen._paths("demo.com")
        paths["base"].mkdir(parents=True)
        paths["url"].write_text("abc.oast.fun")
        rc = oast_listen.cmd_payloads("demo.com", "sqli")
        assert rc == 0
        # Output file should use canonical class name in filename
        assert (paths["base"] / "payloads_SQLi.txt").is_file()
