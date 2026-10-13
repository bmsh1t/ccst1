"""Current native Skill and method-reference routing surface.

Descriptions receive a lexical smoke check, not a model capability score.
Direct knowledge/owner lookups retain readable references without another Skill.
The investigation/source pair must preserve its reciprocal responsibility boundary.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = REPO_ROOT / "skills"
CASES_PATH = REPO_ROOT / "tests" / "skill-validator" / "cases" / "skill_routing_ab_cases.json"


def _description(skill_id: str) -> str:
    text = (SKILLS_DIR / skill_id / "SKILL.md").read_text(encoding="utf-8")
    match = re.search(r"^description:\s*(.+)$", text, re.MULTILINE)
    assert match, f"no description frontmatter in {skill_id}"
    return match.group(1).strip().strip('"\'')


def _stem(tok: str) -> str:
    """Crude singular normalization so endpoint/endpoints match."""
    return tok[:-1] if tok.endswith("s") and len(tok) > 5 else tok


def _trigger_tokens(skill_id: str) -> set[str]:
    """Headline trigger tokens: the words of the Use-when clause."""
    desc = _description(skill_id).lower()
    # Take the trigger clause up to the first period.
    clause = desc.split(".")[0]
    stop = {"use", "when", "a", "an", "the", "or", "and", "of", "to", "is",
            "are", "in", "on", "for", "with", "that", "this", "must", "be",
            "needs", "need", "named", "names", "work", "before", "after",
            "more", "than", "one", "any", "its", "it"}
    return {
        _stem(tok) for tok in re.findall(r"[a-z][a-z0-9-]+", clause)
        if tok not in stop and len(tok) > 3
    }


def test_routing_cases_reference_real_skills_and_method_owners():
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    on_disk = {p.name for p in SKILLS_DIR.iterdir() if (p / "SKILL.md").is_file()}
    assert set(data["meta"]["skills"]) == on_disk
    for case in data["cases"]:
        assert ("expected" in case) != ("expected_reference" in case), case["moment"]
        if "expected" in case:
            assert case["expected"] in on_disk, case["moment"]
            assert case["expected"] not in case["distractors"], case["moment"]
        else:
            assert (REPO_ROOT / case["expected_reference"]).is_file(), case["moment"]
        for distractor in case["distractors"]:
            assert distractor in on_disk, case["moment"]


def test_routing_case_distractors_do_not_outmatch_expected():
    """The expected skill's trigger tokens must not be a strict subset of a
    distractor's on the case's own moment text — the cheap lexical form of
    'the distractor would win this moment'."""
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    for case in data["cases"]:
        if "expected_reference" in case:
            continue
        moment = case["moment"].lower()
        # Lexical overlap: each listed distractor must not name the case's
        # core trigger words more strongly than the expected skill does.
        core = {_stem(tok) for tok in re.findall(r"[a-z][a-z0-9-]+", moment)
                if len(tok) > 4}
        exp_score = len(core & _trigger_tokens(case["expected"]))
        for distractor in case["distractors"]:
            dist_score = len(core & _trigger_tokens(distractor))
            assert dist_score <= exp_score, (
                f"{case['moment']!r}: distractor {distractor} (score "
                f"{dist_score}) lexically outmatches {case['expected']} "
                f"(score {exp_score}) on the case's core words"
            )


# The investigation core and source specialist link to each other's owner.
MUTUAL_PAIRS = [
    (
        "src-hunting",
        "whitebox-audit",
    ),
]


def test_confusion_pairs_name_each_others_territory():
    """A source question delegates locally; global hypotheses stay with the core."""
    for core_id, source_id in MUTUAL_PAIRS:
        core = (SKILLS_DIR / core_id / "SKILL.md").read_text(encoding="utf-8")
        source = (SKILLS_DIR / source_id / "SKILL.md").read_text(encoding="utf-8")
        assert f"skills/{source_id}/SKILL.md" in core
        assert f"skills/{core_id}/SKILL.md" in source
        assert "competing hypotheses" in _description(core_id)
        assert "reachable inputs" in _description(source_id)
        assert "global reprioritization returns here" in core
        assert "retains the global" in source


def test_direct_only_skills_carry_scope_gates():
    """The four direct-only skills keep their explicit-scope trigger in the
    description (route_mode governance lives in this one sentence, not in a
    registry)."""
    for skill_id in ("cicd-security", "mobile-pentest", "meme-coin-audit", "web3-audit"):
        desc = _description(skill_id).lower()
        assert "explicitly in scope" in desc, skill_id
