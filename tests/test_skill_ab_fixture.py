"""Offline A/B row, oracle, and pairing fixtures.

The fixture intentionally contains no model or network call.  It only proves
that the narrow JSONL boundary does not turn malformed rows into a baseline.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_DIR = REPO_ROOT / "tests" / "skill-validator"
FIXTURE_PATH = VALIDATOR_DIR / "cases" / "ab_metric_fixture.jsonl"
if str(VALIDATOR_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATOR_DIR))

from ab_runner import (  # noqa: E402
    load_existing_evaluation,
    load_jsonl,
    main,
    offline_row,
    summarize_rows,
    write_jsonl,
)


def _fixture_rows():
    return [
        offline_row("safe-trap", "skills_off", "vulnerable", oracle_label="safe"),
        offline_row("safe-trap", "skills_on", "safe", oracle_label="safe"),
        offline_row(
            "vulnerable-control", "skills_off", "safe", oracle_label="vulnerable"
        ),
        offline_row(
            "vulnerable-control", "skills_on", "vulnerable", oracle_label="vulnerable"
        ),
    ]


def test_offline_fixture_reports_tpr_fpr_and_paired_delta():
    result = summarize_rows(_fixture_rows())

    assert result["invalid_row_count"] == 0
    assert result["tpr"] == {"skills_off": 0.0, "skills_on": 1.0}
    assert result["fpr"] == {"skills_off": 1.0, "skills_on": 0.0}
    assert result["paired_delta"]["accuracy"] == 1.0
    assert result["paired_delta"]["tpr"] == 1.0
    assert result["paired_delta"]["fpr"] == -1.0
    assert result["paired_delta"]["improved"] == ["safe-trap", "vulnerable-control"]
    assert result["paired_delta"]["case_count"] == 2
    assert result["metrics"]["skills_off"]["cost_usd"]["observed"] == 0
    assert all(
        row[field] is None
        for row in _fixture_rows()
        for field in ("turns", "tokens", "cost_usd", "duration_ms")
    )


def test_unknown_condition_and_missing_fields_are_invalid_not_baseline():
    rows = _fixture_rows()
    rows[0]["condition"] = "baseline"
    del rows[1]["duration_ms"]
    result = summarize_rows(rows)

    assert result["invalid_row_count"] == 2
    assert result["valid_row_count"] == 2
    assert result["conditions"]["skills_off"]["case_count"] == 1
    assert result["conditions"]["skills_on"]["case_count"] == 1
    # The surviving vulnerable-control pair is still a legitimate comparison;
    # only the malformed rows are excluded.
    assert result["paired_delta"]["case_count"] == 1
    errors = [error for item in result["invalid_rows"] for error in item["errors"]]
    assert any("unknown condition" in error for error in errors)
    assert "missing field: duration_ms" in errors


def test_repeated_runs_pair_by_case_and_rep_and_report_unpaired_rows():
    rows = [
        offline_row("safe-trap", "skills_off", "safe", rep=1, oracle_label="safe"),
        offline_row("safe-trap", "skills_on", "safe", rep=1, oracle_label="safe"),
        offline_row("safe-trap", "skills_off", "safe", rep=2, oracle_label="safe"),
        offline_row("safe-trap", "skills_on", "vulnerable", rep=2, oracle_label="safe"),
        offline_row(
            "vulnerable-control", "skills_off", "safe", rep=1, oracle_label="vulnerable"
        ),
    ]

    result = summarize_rows(rows)

    assert result["paired_delta"]["case_count"] == 2
    assert result["unpaired_pair_count"] == 1
    assert result["unpaired_pairs"] == [
        {"case_id": "vulnerable-control", "rep": 1, "conditions": ["skills_off"]}
    ]


def test_paired_resource_metrics_include_on_minus_off_delta():
    rows = [
        offline_row(
            "CASE",
            "skills_off",
            "safe",
            oracle_label="safe",
            turns=2,
            tokens=100,
            cost_usd=0.2,
            duration_ms=1000,
        ),
        offline_row(
            "CASE",
            "skills_on",
            "safe",
            oracle_label="safe",
            turns=3,
            tokens=130,
            cost_usd=0.3,
            duration_ms=1400,
        ),
    ]

    result = summarize_rows(rows)

    assert result["paired_metrics"]["turns"] == {"observed": 1, "mean_delta": 1.0}
    assert result["paired_metrics"]["tokens"] == {"observed": 1, "mean_delta": 30.0}
    assert result["paired_metrics"]["cost_usd"]["observed"] == 1
    assert result["paired_metrics"]["cost_usd"]["mean_delta"] == pytest.approx(0.1)
    metric_delta = result["paired_delta"]["cases"][0]["metric_delta"]
    assert metric_delta["turns"] == pytest.approx(1)
    assert metric_delta["tokens"] == pytest.approx(30)
    assert metric_delta["cost_usd"] == pytest.approx(0.1)
    assert metric_delta["duration_ms"] == pytest.approx(400)


def test_behavior_metrics_cover_evidence_routing_and_recovery_without_filling_gaps():
    rows = [
        offline_row(
            "CASE",
            "skills_off",
            "safe",
            oracle_label="safe",
            behavior={
                "hypothesis_selected": False,
                "action_selected": True,
                "tool_choice_valid": False,
                "evidence_complete": False,
                "duplicate_action": True,
                "invalid_route": True,
                "recovery_success": False,
                "coverage_progress": 1,
                "unsupported_claim": True,
            },
        ),
        offline_row(
            "CASE",
            "skills_on",
            "safe",
            oracle_label="safe",
            behavior={
                "hypothesis_selected": True,
                "action_selected": True,
                "tool_choice_valid": True,
                "evidence_complete": True,
                "duplicate_action": False,
                "invalid_route": False,
                "recovery_success": True,
                "coverage_progress": 3,
                "unsupported_claim": False,
            },
        ),
    ]

    result = summarize_rows(rows)

    assert result["behavior"]["skills_on"]["evidence_complete"] == {
        "observed": 1,
        "mean": 1.0,
    }
    assert result["behavior"]["skills_off"]["duplicate_action"]["mean"] == 1.0
    assert result["paired_behavior"]["coverage_progress"] == {
        "observed": 1,
        "mean_delta": 2.0,
    }
    assert result["paired_delta"]["cases"][0]["behavior_delta"]["invalid_route"] == -1.0


def test_mismatched_pair_oracle_is_invalid_and_excluded_from_both_arms():
    rows = [
        offline_row("CASE", "skills_off", "safe", oracle_label="safe"),
        offline_row("CASE", "skills_on", "safe", oracle_label="vulnerable"),
    ]

    result = summarize_rows(rows)

    assert result["valid_row_count"] == 0
    assert result["invalid_row_count"] == 2
    assert all(stats["case_count"] == 0 for stats in result["conditions"].values())
    assert result["paired_delta"]["case_count"] == 0
    assert all(
        "paired oracle truth mismatch" in error
        for item in result["invalid_rows"]
        for error in item["errors"]
    )


def test_failed_oracle_is_recorded_but_excluded_from_metrics():
    rows = _fixture_rows()
    rows.append(
        offline_row(
            "oracle-failed",
            "skills_off",
            "vulnerable",
            oracle_status="invalid",
            oracle_label="vulnerable",
        )
    )

    result = summarize_rows(rows)

    assert result["row_count"] == 5
    assert result["valid_row_count"] == 4
    assert result["invalid_row_count"] == 1
    assert "oracle is not usable" in result["invalid_rows"][-1]["errors"]


def test_existing_web2_cases_and_scoring_stay_the_offline_source():
    result = load_existing_evaluation()

    assert result["summary"]["case_count"] == len(result["rows"])
    assert result["summary"]["case_count"] > 0
    assert all(
        {"baseline_score", "enhanced_score", "max_score"} <= row.keys()
        for row in result["rows"]
    )


def test_jsonl_round_trip_preserves_offline_null_metrics(tmp_path):
    path = tmp_path / "nested" / "ab.jsonl"
    write_jsonl(path, [_fixture_rows()[0]])

    loaded = load_jsonl(path)
    assert loaded[0]["turns"] is None
    assert summarize_rows(loaded)["valid_row_count"] == 1


def test_strict_cli_returns_error_for_unpaired_rows(tmp_path, capsys):
    path = tmp_path / "ab.jsonl"
    write_jsonl(path, [_fixture_rows()[0]])

    assert main([str(path), "--strict", "--json"]) == 2
    assert '"unpaired_pair_count": 1' in capsys.readouterr().out


def test_repository_fixture_is_cli_ready():
    result = summarize_rows(load_jsonl(FIXTURE_PATH))

    assert result["invalid_row_count"] == 0
    assert result["paired_delta"]["case_count"] == 2
