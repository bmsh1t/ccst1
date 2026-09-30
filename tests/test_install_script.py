from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

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
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1, result.stderr + result.stdout

    active_command = runtime_commands / "sync-check.md"
    expected = (REPO_ROOT / "commands" / "sync-check.md").read_text(encoding="utf-8")

    assert not active_command.exists()
    assert disabled_command.read_text(encoding="utf-8") == "old disabled content\n"
    assert "Preserved conflicting files" in result.stdout


def test_install_script_copies_shared_skill_markdown_files(tmp_path):
    home = tmp_path / "home"
    env = os.environ.copy()
    env["HOME"] = str(home)

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh")],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr + result.stdout

    installed_protocol = home / ".claude" / "skills" / "runtime-protocol.md"
    expected = (REPO_ROOT / "skills" / "runtime-protocol.md").read_text(encoding="utf-8")

    assert installed_protocol.read_text(encoding="utf-8") == expected

    installed_bug_bounty = home / ".claude" / "skills" / "bug-bounty" / "SKILL.md"
    modular_bug_bounty = REPO_ROOT / "skills" / "bug-bounty" / "SKILL.md"
    assert installed_bug_bounty.read_bytes() == modular_bug_bounty.read_bytes()
    assert not (REPO_ROOT / "SKILL.md").exists()


def test_install_script_recursively_copies_managed_skill_resources(tmp_path):
    home = tmp_path / "home"
    env = os.environ.copy()
    env["HOME"] = str(home)

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh")],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
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
    assert Path("SKILL.md") in installed_files
    assert not any(path.parts[0] == "references" for path in installed_files)


def test_install_script_produces_runtime_doctor_clean_tree(tmp_path):
    home = tmp_path / "home"
    env = os.environ.copy()
    env["HOME"] = str(home)

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh")],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
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


def test_install_script_skips_optional_mcp_prompts_without_a_tty(tmp_path):
    """A staged/CI install must not block on an inherited controlling tty."""
    home = tmp_path / "home"
    env = os.environ.copy()
    env["HOME"] = str(home)

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh")],
        cwd=REPO_ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "Set up Burp MCP now? (y/N): n" in result.stdout


def test_install_upgrade_and_repeat_preserve_user_state(tmp_path):
    from tools.target_store import TargetStore

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    for name in ("commands", "skills", "agents"):
        shutil.copytree(REPO_ROOT / name, checkout / name)
    shutil.copy2(REPO_ROOT / "install.sh", checkout / "install.sh")
    (checkout / "tools").mkdir()
    for name in ("runtime_doctor.py", "artifact_io.py"):
        shutil.copy2(REPO_ROOT / "tools" / name, checkout / "tools" / name)
    markdown_inputs = []
    for kind in ("commands", "agents"):
        for name, excluded in (
            ("local.patch.md", True), ("local.PATCH.md", True), ("local.PaTcH.md", True),
            ("local.md", False), ("local.patch-notes.md", False),
        ):
            source = checkout / kind / name
            body = f"{kind}/{name}\n".encode()
            source.write_bytes(body)
            markdown_inputs.append((source, body, excluded))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("basename", "dirname", "mkdir", "cp", "cat", "grep", "python3"):
        executable = shutil.which(name)
        if not executable:
            pytest.skip(f"installer test requires {name}")
        (bin_dir / name).symlink_to(executable)
    user_dir = tmp_path / "user"
    runtime = user_dir / ".claude"
    env = {"PATH": str(bin_dir), "HOME": str(user_dir)}

    def install():
        result = subprocess.run(["/bin/bash", str(checkout / "install.sh")], cwd=checkout, env=env,
                                stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr + result.stdout
        for source, body, excluded in markdown_inputs:
            installed = runtime / runtime_doctor.RUNTIME_SUBDIRS[source.parent.name] / source.name
            assert source.read_bytes() == body
            if excluded:
                assert not installed.exists()
            else:
                assert installed.read_bytes() == body

    install()
    assert runtime_doctor.compare_runtime(checkout, runtime)["clean"]
    disabled = runtime / "commands/.disabled.sync-check.md"
    (runtime / "commands/sync-check.md").rename(disabled)
    preserved = {
        runtime / "settings.json": b'{"userPreference":true}\n',
        runtime / "skills/user-skill/SKILL.md": b"User-owned skill\n",
        checkout / ".private/auth.json": b'{"bearer":"fixture-only"}\n',
    }
    for path, body in preserved.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    store = TargetStore(checkout, "release.test")
    store.initialize()
    store.remember(command_id="saved", kind="note", statement="Preserve upgrade context",
                   conditions="fixture", reopen_when="", next_intent="", evidence=[], actor="test")
    binding = store.binding()
    source_command = checkout / "commands/sync-check.md"
    source_command.write_text(source_command.read_text() + "\nUpdated command\n")
    source_resource = checkout / "skills/security-arsenal/release.txt"
    source_resource.write_text("new resource\n")
    stale = runtime / "skills/security-arsenal/retired.txt"
    stale.write_text("old managed resource\n")
    for _ in range(2):
        install()
        assert not (runtime / "commands/sync-check.md").exists()
        assert disabled.read_bytes() == source_command.read_bytes()
        assert (runtime / "skills/security-arsenal/release.txt").read_bytes() == source_resource.read_bytes()
        assert all(path.read_bytes() == body for path, body in preserved.items())
        assert store.binding() == binding
        assert store.experience_page()["items"][0]["statement"] == "Preserve upgrade context"
        comparison = runtime_doctor.compare_runtime(checkout, runtime)
        assert not comparison["clean"]  # unowned extra is visible, never deleted
        assert stale.exists()
    runtime_doctor.sync_runtime(checkout, runtime, kinds=["skills"], prune=True)
    assert stale.exists()  # no ownership receipt: preserve the unknown file
    assert all(path.read_bytes() == body for path, body in preserved.items())
