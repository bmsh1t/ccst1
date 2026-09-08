"""Guard the fixed decision cases used by the AI-native convergence A/B."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_DIR = REPO_ROOT / "tests" / "skill-validator"
if str(VALIDATOR_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATOR_DIR))

from ab_runner import load_jsonl  # noqa: E402


CASE_FILE = VALIDATOR_DIR / "cases" / "ai_native_skill_convergence_ab.jsonl"
EXPECTED_CASES = {
    "A01_sparse_discovery",
    "A02_actor_object_priority",
    "A03_stack_only_signal",
    "A04_high_value_roi",
    "A05_repeated_progress",
    "A06_fresh_evidence_reopen",
    "A07_missing_validation_proof",
    "A08_residual_inventory",
}


@pytest.mark.parametrize(
    ("case_file", "expected_cases"),
    [
        (CASE_FILE, EXPECTED_CASES),
        (
            VALIDATOR_DIR / "cases" / "evidence_counterexamples_ab.jsonl",
            {
                "A09_scoped_negative_with_residual_session",
                "A10_local_denial_is_not_global_repair",
                "A11_shared_login_is_not_component_identity",
                "A12_login_fallback_preserves_unknown",
            },
        ),
    ],
    ids=["baseline", "evidence-counterexamples"],
)
def test_ai_native_decision_cases_are_fixed_and_parseable(case_file, expected_cases):
    rows = load_jsonl(case_file)

    assert len(rows) == len(expected_cases)
    assert {row["case_id"] for row in rows} == expected_cases
    assert {row["oracle_status"] for row in rows} == {"passed"}
    assert {row["oracle_label"] for row in rows} == {"safe", "vulnerable"}
    assert all(isinstance(row["prompt"], str) and row["prompt"].strip() for row in rows)
