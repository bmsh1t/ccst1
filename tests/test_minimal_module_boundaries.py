"""Keep the evidence-based no-op module-boundary decision visible."""

from pathlib import Path


def test_boundary_review_names_large_modules_and_records_noop():
    repo = Path(__file__).resolve().parents[1]
    review = (repo / "docs/minimal-module-boundaries.md").read_text(encoding="utf-8")
    for module in (
        "tools/autopilot_state.py",
        "tools/checkpoint.py",
        "tools/validation_runner.py",
        "tools/context_pack.py",
        "tools/surface.py",
        "tools/action_queue.py",
    ):
        assert f"| `{module}` |" in review
    assert "No production extraction is justified" in review
