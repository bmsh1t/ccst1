"""Current entry and complete-module reachability; no model routing score."""

from __future__ import annotations

import json
from pathlib import Path

from tools.skill_reference_contract import CORE_SKILL_PATH, INTERNAL_MODULE_NAMES

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = REPO_ROOT / "skills"
CASES_PATH = REPO_ROOT / "tests" / "skill-validator" / "cases" / "skill_routing_ab_cases.json"


def test_routing_cases_reference_real_skills_and_method_owners():
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    assert list(SKILLS_DIR.rglob("SKILL.md")) == [REPO_ROOT / CORE_SKILL_PATH]
    assert data["meta"]["skills"] == ["src-hunter"]
    core = (REPO_ROOT / CORE_SKILL_PATH).read_text(encoding="utf-8")
    for name in INTERNAL_MODULE_NAMES:
        relative = f"modules/{name}.md"
        module = SKILLS_DIR / "src-hunter" / relative
        assert relative in core
        text = module.read_text(encoding="utf-8")
        assert not text.startswith("---")
        assert "../SKILL.md" in text
    for case in data["cases"]:
        assert ("expected" in case) != ("expected_reference" in case), case["moment"]
        if "expected" in case:
            assert case["expected"] == "src-hunter", case["moment"]
            if "expected_module" in case:
                assert case["expected_module"] in INTERNAL_MODULE_NAMES, case["moment"]
        else:
            assert (REPO_ROOT / case["expected_reference"]).is_file(), case["moment"]


def test_direct_only_modules_carry_scope_gates():
    for name in ("cicd-security", "mobile-pentest", "meme-coin-audit", "web3-audit"):
        text = (SKILLS_DIR / "src-hunter" / "modules" / f"{name}.md").read_text(encoding="utf-8")
        assert "explicitly in scope" in text, name
