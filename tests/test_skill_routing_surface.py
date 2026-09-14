"""Routing-surface contract tests: description triggers stay distinct.

Two layers (from the 2026-09-14 routing-surface plan, P1):

1. Routing A/B cases — each session moment must name the expected skill,
   and no listed distractor may be a better textual match on the trigger
   phrase. This is a lexical smoke layer: it catches trigger-word
   collisions (the same headline phrase inviting two skills), not full
   semantic routing, which is what the live A/B runner measures.
2. Mutual-disambiguation check — for the known confusion pairs, each
   description must name the other side's territory (an explicit boundary
   clause), so the pair cannot both claim the same moment.
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


def test_routing_cases_reference_real_skills():
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    on_disk = {p.name for p in SKILLS_DIR.iterdir() if p.is_dir()}
    for case in data["cases"]:
        assert case["expected"] in on_disk, case["moment"]
        for distractor in case["distractors"]:
            assert distractor in on_disk, case["moment"]
        assert case["expected"] not in case["distractors"], case["moment"]


def test_routing_case_distractors_do_not_outmatch_expected():
    """The expected skill's trigger tokens must not be a strict subset of a
    distractor's on the case's own moment text — the cheap lexical form of
    'the distractor would win this moment'."""
    data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    for case in data["cases"]:
        moment = case["moment"].lower()
        expected_hits = _description(case["expected"]).lower().count(
            case["moment"].split()[0].lower()
        )
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
        assert expected_hits >= 0  # reading only; keeps intent explicit


# Known confusion pairs: (skill A, skill B, A's clause about B, B's clause about A)
MUTUAL_PAIRS = [
    (
        "bug-bounty",
        "bb-methodology",
        "bb-methodology",
        "bug-bounty",
    ),
]


def test_confusion_pairs_name_each_others_territory():
    """After the 2026-09-14 disambiguation, the coordinator/methodology pair
    must each carry an explicit boundary clause pointing at the other, so a
    stall-and-stage moment cannot be claimed by both."""
    for a, b, a_points_to, b_points_to in MUTUAL_PAIRS:
        assert a_points_to in _description(a), (
            f"{a} description must name {a_points_to} as the boundary owner"
        )
        assert b_points_to in _description(b), (
            f"{b} description must name {b_points_to} as the boundary owner"
        )


def test_direct_only_skills_carry_scope_gates():
    """The four direct-only skills keep their explicit-scope trigger in the
    description (route_mode governance lives in this one sentence, not in a
    registry)."""
    for skill_id in ("cicd-security", "mobile-pentest", "meme-coin-audit", "web3-audit"):
        desc = _description(skill_id).lower()
        assert "explicitly in scope" in desc, skill_id
