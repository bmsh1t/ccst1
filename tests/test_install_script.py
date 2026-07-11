from __future__ import annotations

import os
import subprocess
from pathlib import Path

from tools import runtime_doctor


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


def test_install_script_recursively_copies_managed_skill_resources(tmp_path):
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

    repo_skill = REPO_ROOT / "skills" / "security-arsenal"
    runtime_skill = home / ".claude" / "skills" / "security-arsenal"
    expected_files = {
        path.relative_to(repo_skill)
        for path in repo_skill.rglob("*")
        if path.is_file()
    }
    installed_files = {
        path.relative_to(runtime_skill)
        for path in runtime_skill.rglob("*")
        if path.is_file()
    }

    assert installed_files == expected_files
    for relative_path in expected_files:
        assert (runtime_skill / relative_path).read_bytes() == (
            repo_skill / relative_path
        ).read_bytes()
    assert Path("references/bypass-patterns.md") in installed_files
    assert Path("METHODOLOGY_CHEATSHEET.md") in installed_files
    assert Path("REFERENCES.md") in installed_files


def test_install_script_produces_runtime_doctor_clean_tree(tmp_path):
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
    payload = runtime_doctor.compare_runtime(
        repo_root=REPO_ROOT,
        runtime_root=home / ".claude",
    )

    assert payload["clean"] is True
    assert payload["drift_count"] == 0
    assert all(
        result["counts"]["missing"] == 0
        and result["counts"]["diff"] == 0
        and result["counts"]["extra"] == 0
        for result in payload["kinds"]
    )
