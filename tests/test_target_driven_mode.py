"""Regression tests for target-driven Claude CLI and local-target behavior."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _combined_docs() -> str:
    return "\n".join(
        (REPO_ROOT / path).read_text(encoding="utf-8")
        for path in (
            "CLAUDE.md",
            "agents/autopilot.md",
            "commands/autopilot.md",
            "commands/hunt.md",
            "commands/recon.md",
            "commands/scope.md",
            "commands/validate.md",
        )
    ).lower()


def test_autopilot_docs_keep_target_driven_flow_and_document_ctf_override():
    combined = _combined_docs()

    assert "active execution target set" in combined
    assert "ctf_mode" in combined
    assert "高仿真 ctf 靶场" in combined
    assert "public-program, written-permission, or ownership-confirmation" in combined
    assert "advisory audit/replay" in combined
    assert "external policy" not in combined
    assert "localhost/private ip/cidr/list" in combined or "localhost, private ips, cidrs, and list inputs" in combined
    assert "ctf_mode" in combined


def test_claude_autopilot_does_not_create_a_target_nature_preflight():
    autopilot = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
    recon = (REPO_ROOT / "commands" / "recon.md").read_text(encoding="utf-8")
    agent_doc = (REPO_ROOT / "agents" / "autopilot.md").read_text(encoding="utf-8")

    assert "Run the embedded bootstrap before reading lane contracts, Resin configuration" in autopilot
    assert "do not ask whether" not in autopilot
    assert "Before the first network lane for a public target" not in autopilot
    assert "Start directly with **Run This**" in recon
    assert "## Authorization Posture" not in recon
    assert "Do not create a separate target-nature" not in agent_doc
    assert "Do not create a separate target-nature" not in recon
    assert "不要以目标性质、公开/私有、归属或授权确认作为常规探索的额外门槛" in (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")


def test_validate_docs_keep_exact_7_question_gate_language():
    text = (REPO_ROOT / "commands" / "validate.md").read_text(encoding="utf-8").lower()

    assert "7-question gate" in text
    assert "runs the 7-question gate" in text
    assert "q8" not in text


def test_recon_docs_keep_bulk_recon_enabled_and_document_ctf_override():
    combined = "\n".join(
        (REPO_ROOT / path).read_text(encoding="utf-8")
        for path in (
            "CLAUDE.md",
            "commands/recon.md",
            "agents/recon-agent.md",
            "skills/web2-recon/SKILL.md",
        )
    ).lower()

    assert "recon-discovered subdomains" in combined
    assert "subfinder" in combined
    assert "httpx" in combined
    assert "katana" in combined
    assert "gau" in combined
    assert "bounded directory/parameter fuzzing" in combined
    assert "ctf_mode" in combined
