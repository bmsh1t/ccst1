"""Regression tests for /hunt command workflow docs."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_hunt_command_uses_context_pack_before_active_probes():
    text = _read("commands/hunt.md")

    assert "python3 tools/context_pack.py --target target.com" in text
    assert "Run context-pack" in text
    assert "minimal context pack" in text


def test_hunt_command_uses_checkpoint_for_writeback_and_rotation():
    text = _read("commands/hunt.md")

    assert "python3 tools/checkpoint.py --target target.com" in text
    assert "checkpoint automation" in text
    assert "Only use `--apply-target-memory`" in text
    assert "Use the checkpoint output to update target memory" in text
