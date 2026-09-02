"""Focused regression checks for the AI-first Skill/report contracts."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(*paths: str) -> str:
    return "\n".join((REPO_ROOT / path).read_text(encoding="utf-8") for path in paths)


def test_security_arsenal_is_a_thin_ai_first_contract():
    path = REPO_ROOT / "skills/security-arsenal/SKILL.md"
    text = path.read_text(encoding="utf-8")

    assert len(text.splitlines()) <= 180
    for marker in (
        "## XSS PAYLOADS",
        "169.254.169.254",
        "UNION SELECT",
        "<script>",
        "wscat",
        "METHODOLOGY_CHEATSHEET",
    ):
        assert marker not in text
    for marker in (
        "## Decision Tree",
        "## ROI Selection",
        "## Phase Switch",
        "## Stateful Continuity",
        "## Evidence Gate",
        "## Canonical Write-Back",
        "## AI Autonomy and Red Lines",
    ):
        assert marker in text

    reference_dir = REPO_ROOT / "skills/security-arsenal/references"
    assert not list(reference_dir.glob("*.md"))


def test_validation_uses_replayable_artifacts_without_fixed_http_or_count_gates():
    text = _read(
        "skills/triage-validation/SKILL.md",
        "commands/triage.md",
        "commands/validate.md",
        "agents/validator.md",
    )

    assert "target-bound" in text
    assert "browser" in text and "frame" in text and "state" in text
    assert "lowest-risk evidence" in text
    assert "there is no universal numeric cutoff" in text
    assert "Can attacker do this RIGHT NOW with a real HTTP request?" not in text
    assert "More than 2 preconditions simultaneously required" not in text
    assert "Confirmed with a target-bound replayable artifact" in text
    assert "Gate 0 (30 sec)" not in text
    assert "HTTP when applicable; browser, frame, state, or OOB equivalent otherwise" in text


def test_triage_gate_is_protocol_neutral_and_delivery_mode_aware():
    skill = (REPO_ROOT / "skills/triage-validation/SKILL.md").read_text(encoding="utf-8")
    triage = (REPO_ROOT / "commands/triage.md").read_text(encoding="utf-8")

    assert "target-bound replayable artifact" in skill
    assert "actual HTTP requests, not code reading alone" not in skill
    assert "Every applicable gate must pass" in skill
    assert "local/lab" in skill
    assert "external disclosed-report checks are" in triage
    assert "record the Q7b identity boundary" in triage


def test_report_contract_consumes_one_structured_cvss_owner():
    command, skill, writer, rules = (
        _read("commands/report.md"),
        _read("skills/report-writing/SKILL.md"),
        _read("agents/report-writer.md"),
        _read("rules/reporting.md"),
    )

    assert "skills/report-writing/SKILL.md` is the report-only contract owner" in command
    for text in (command, skill, writer):
        assert "cvss.version" in text
        assert "cvss.score" in text
        assert "cvss.vector" in text
    assert "CVSS 4.0\n  calculation included" not in writer
    assert "HTTP request when applicable" in writer
    assert "Method: [GET/POST/PUT/DELETE]" not in writer
    assert "tools/validate.py` is the only scoring producer" in rules
    assert "CVSS 4.0 Calculation Guide" not in command
    assert "CVSS Calibration" not in skill
    assert "CVSS Calibration Notes" not in command
    assert "slightly aggressive" not in skill


def test_report_only_skill_has_an_explicit_non_default_route():
    from tools.context_pack import SKILL_CATALOG, SKILL_PATHS

    assert SKILL_CATALOG["report-writing"]["route_mode"] == "report-only"
    assert "report-writing" not in SKILL_PATHS
    command = _read("commands/report.md")
    writer = _read("agents/report-writer.md")
    assert "skills/report-writing/SKILL.md" in command
    assert "skills/report-writing/SKILL.md" in writer


def test_ai_first_routes_do_not_reintroduce_fixed_specialist_sequences():
    chain = _read("commands/chain.md", "agents/chain-builder.md")
    credential = _read("skills/credential-attack/SKILL.md")
    recon = _read("skills/web2-recon/SKILL.md")
    vuln = _read("skills/web2-vuln-classes/SKILL.md")
    web3 = _read("commands/web3-audit.md", "agents/web3-auditor.md")
    token = _read("commands/token-scan.md", "agents/token-auditor.md")

    assert "not an execution order" in chain
    assert "progress fingerprint repeats" in chain
    assert "Immediately Check B" not in chain
    assert "tools/wordlist_engine.sh" not in credential
    assert "password → all users" not in credential
    assert "must never write or mutate the rebuildable Surface projection directly" in recon
    assert "not a fixed checklist" in vuln
    assert "score >= 6/10" not in web3
    assert "5-Minute Rule" not in token
