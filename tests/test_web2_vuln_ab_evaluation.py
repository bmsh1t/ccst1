"""Regression tests for the web2-vuln-classes A/B evaluator."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "tests" / "skill-validator" / "web2_vuln_ab_eval.py"
SPEC = importlib.util.spec_from_file_location("web2_vuln_ab_eval", SCRIPT)
assert SPEC and SPEC.loader
web2_vuln_ab_eval = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = web2_vuln_ab_eval
SPEC.loader.exec_module(web2_vuln_ab_eval)


def test_web2_vuln_ab_cases_keep_post_slim_signal_coverage():
    result = web2_vuln_ab_eval.evaluate_cases(REPO_ROOT)
    summary = result["summary"]

    assert summary["case_count"] >= 10
    assert summary["web2_skill_lines"] < 700
    assert summary["enhanced_total"] >= summary["baseline_total"]
    assert summary["enhanced_total"] == summary["max_total"]
    assert not summary["cases_missing_even_enhanced"]
    assert not summary["route_gap_cases"]
    assert all(row["selected_skill"] == row["expected_skill"] for row in result["rows"])


def test_web2_vuln_ab_report_mentions_interpretation():
    result = web2_vuln_ab_eval.evaluate_cases(REPO_ROOT)
    report = web2_vuln_ab_eval.format_markdown(result)

    assert "Deterministic local A/B" in report
    assert "future live LLM A/B" in report
    assert "post-slim regression baseline" in report
    assert "| Case | Lane | Selected Skill |" in report
