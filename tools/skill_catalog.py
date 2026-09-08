"""Dependency-free Skill identity, routing modes, and route metadata."""

from __future__ import annotations


SKILL_ROUTE_MODES = {"primary", "direct-only", "reference-only", "report-only"}

SKILL_CATALOG = {
    "bb-methodology": {
        "path": "skills/bb-methodology/SKILL.md",
        "route_mode": "primary",
        "required_dimensions": ["hypothesis", "coverage", "pivot", "stop_condition"],
    },
    "bug-bounty": {
        "path": "skills/bug-bounty/SKILL.md",
        "route_mode": "primary",
        "required_dimensions": ["scope", "evidence", "hypothesis", "next_action"],
    },
    "credential-attack": {
        "path": "skills/credential-attack/SKILL.md",
        "route_mode": "primary",
        "required_dimensions": [
            "entry_signal",
            "user_source",
            "mode_contract",
            "preflight",
            "stop_condition",
            "evidence_resume",
        ],
    },
    "triage-validation": {
        "path": "skills/triage-validation/SKILL.md",
        "route_mode": "primary",
        "required_dimensions": ["baseline", "variant", "impact", "replay"],
    },
    "web2-recon": {
        "path": "skills/web2-recon/SKILL.md",
        "route_mode": "primary",
        "required_dimensions": ["surface", "source", "browser", "scope"],
    },
    "web2-vuln-classes": {
        "path": "skills/web2-vuln-classes/SKILL.md",
        "route_mode": "primary",
        "required_dimensions": [
            "vulnerability_family",
            "parameter",
            "encoding",
            "auth",
            "sibling",
            "workflow",
            "chain",
        ],
    },
    "cicd-security": {
        "path": "skills/cicd-security/SKILL.md",
        "route_mode": "direct-only",
    },
    "meme-coin-audit": {
        "path": "skills/meme-coin-audit/SKILL.md",
        "route_mode": "direct-only",
    },
    "mobile-pentest": {
        "path": "skills/mobile-pentest/SKILL.md",
        "route_mode": "direct-only",
    },
    "web3-audit": {
        "path": "skills/web3-audit/SKILL.md",
        "route_mode": "direct-only",
    },
    "security-arsenal": {
        "path": "skills/security-arsenal/SKILL.md",
        "route_mode": "reference-only",
    },
    "report-writing": {
        "path": "skills/report-writing/SKILL.md",
        "route_mode": "report-only",
    },
}

SKILL_PATHS = {
    skill_id: item["path"]
    for skill_id, item in SKILL_CATALOG.items()
    if item["route_mode"] == "primary"
}

SKILL_TEST_DIMENSIONS = {
    skill_id: list(item["required_dimensions"])
    for skill_id, item in SKILL_CATALOG.items()
    if item["route_mode"] == "primary"
}


def skill_route(skill: str, reason: str) -> dict:
    """Return the canonical route metadata for an owner-generated action."""
    return {
        "skill_id": skill,
        "skill_path": SKILL_PATHS[skill],
        "reason": str(reason or "").strip(),
        "required_dimensions": list(SKILL_TEST_DIMENSIONS.get(skill, [])),
    }
