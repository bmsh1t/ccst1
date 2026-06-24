"""Regression tests for /pickup command documentation."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_pickup_command_surfaces_checkpoint_followup():
    text = (REPO_ROOT / "commands" / "pickup.md").read_text(encoding="utf-8")

    assert "python3 tools/checkpoint.py --target <target> --no-refresh-coverage" in text
    assert "Checkpoint:" in text
    assert "Target write-back proposals" in text
    assert "[c] Run checkpoint write-back when ready" in text
