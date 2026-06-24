from __future__ import annotations

import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_install_script_preserves_disabled_runtime_command_state(tmp_path):
    home = tmp_path / "home"
    runtime_commands = home / ".claude" / "commands"
    runtime_commands.mkdir(parents=True)

    disabled_command = runtime_commands / ".disabled.sync-check.md"
    disabled_command.write_text("old disabled content\n", encoding="utf-8")

    env = os.environ.copy()
    env["HOME"] = str(home)

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh")],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout

    active_command = runtime_commands / "sync-check.md"
    expected = (REPO_ROOT / "commands" / "sync-check.md").read_text(encoding="utf-8")

    assert not active_command.exists()
    assert disabled_command.read_text(encoding="utf-8") == expected
    assert "preserved disabled state" in result.stdout


def test_install_script_copies_shared_skill_markdown_files(tmp_path):
    home = tmp_path / "home"
    env = os.environ.copy()
    env["HOME"] = str(home)

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh")],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout

    installed_protocol = home / ".claude" / "skills" / "runtime-protocol.md"
    expected = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")

    assert installed_protocol.read_text(encoding="utf-8") == expected
    assert "Installed shared skill file: runtime-protocol.md" in result.stdout
