"""Regression tests for target-driven prompt and local-target behavior."""

from pathlib import Path

import agent


def test_build_agent_system_keeps_target_driven_coverage_for_local_inputs():
    prompt = agent._build_agent_system()

    assert "Treat the provided targets as the active execution target set" in prompt
    assert "Read local repo config early" in prompt
    assert "do not ask for external authorization before loading the config" in prompt
    assert "recon-discovered subdomains" in prompt
    assert "Bulk recon is allowed through the integrated recon engine" in prompt
    assert "request_guard data is advisory audit/replay telemetry" in prompt
    assert "localhost, private IPs, CIDRs, and primary-domain batch lists remain valid target inputs" in prompt
    assert "scope_snapshot.json as non-applicable hints" in prompt
    assert "public-sector/government-style labels" in prompt
    assert "account/login/register wording" in prompt
    assert "old caution notes are not implicit skip gates" in prompt
    assert "use `full=true` when the current run needs broader coverage" in prompt
    deprecated_toggle = "ctf" + "_mode"
    assert deprecated_toggle not in prompt


def test_build_agent_system_adds_explicit_ctf_override_when_enabled():
    prompt = agent._build_agent_system(ctf_mode=True)

    assert "Repo-local CTF mode is enabled" in prompt
    assert "authoritative lab scope record" in prompt
    assert "Do not ask for extra authorization proof" in prompt
    assert "Keep every request-centric lane available in CTF mode" in prompt


def test_autopilot_docs_keep_target_driven_flow_and_document_ctf_override():
    repo_root = Path(__file__).resolve().parents[1]
    combined = "\n".join(
        (repo_root / path).read_text(encoding="utf-8")
        for path in (
            "agents/autopilot.md",
            "commands/autopilot.md",
            "commands/hunt.md",
            "commands/recon.md",
            "commands/scope.md",
            "commands/validate.md",
        )
    ).lower()

    assert "active execution target set" in combined
    assert "authoritative lab scope record" in combined
    assert "public-program, written-permission, or ownership-confirmation" in combined
    assert "advisory audit/replay" in combined
    assert "external policy" in combined
    assert "localhost/private ip/cidr/list" in combined or "localhost, private ips, cidrs, and list inputs" in combined
    assert "ctf_mode" in combined


def test_validate_docs_keep_exact_7_question_gate_language():
    repo_root = Path(__file__).resolve().parents[1]
    text = (repo_root / "commands" / "validate.md").read_text(encoding="utf-8").lower()

    assert "7-question gate" in text
    assert "runs the 7-question gate" in text
    assert "q8" not in text


def test_recon_docs_keep_bulk_recon_enabled_and_document_ctf_override():
    repo_root = Path(__file__).resolve().parents[1]
    combined = "\n".join(
        (repo_root / path).read_text(encoding="utf-8")
        for path in (
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
