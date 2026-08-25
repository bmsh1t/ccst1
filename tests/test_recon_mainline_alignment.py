"""Regression tests for recon mainline prompt/runtime alignment."""

from pathlib import Path


def _read(*parts: str) -> str:
    return (Path(__file__).resolve().parent.parent.joinpath(*parts)).read_text(encoding="utf-8")


def test_mainline_recon_prompts_prefer_integrated_gau_waymore_pipeline():
    autopilot = _read("commands", "autopilot.md")
    recon = _read("commands", "recon.md")
    hunt = _read("commands", "hunt.md")
    recon_agent = _read("agents", "recon-agent.md")
    combined = "\n".join([autopilot, recon, hunt, recon_agent])

    assert "waymore" in combined
    assert "python3 tools/hunt.py --target \"$TARGET\" --recon-only" in recon_agent
    assert "waybackurls" not in combined
