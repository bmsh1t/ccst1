from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
COMMANDS_DIR = REPO_ROOT / "commands"

# 已确认会与 Claude CLI 内置 slash command 冲突的名称。
RESERVED_CLAUDE_COMMANDS = {"doctor", "goal"}


def _command_names() -> set[str]:
    return {path.stem for path in COMMANDS_DIR.glob("*.md")}


def test_project_commands_avoid_known_claude_builtin_names():
    command_names = _command_names()
    collisions = sorted(command_names & RESERVED_CLAUDE_COMMANDS)

    assert collisions == [], (
        "project command names must not collide with known Claude built-ins: "
        + ", ".join(collisions)
    )


def test_sync_check_replaces_legacy_doctor_command():
    command_names = _command_names()

    assert "sync-check" in command_names
    assert "doctor" not in command_names
