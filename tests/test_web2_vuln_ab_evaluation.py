"""Current Web2 material diagnostics retain historical signal scoring."""

from __future__ import annotations

import importlib.util
import hashlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "tests" / "skill-validator" / "web2_vuln_ab_eval.py"
SPEC = importlib.util.spec_from_file_location("web2_vuln_ab_eval", SCRIPT)
assert SPEC and SPEC.loader
web2_vuln_ab_eval = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = web2_vuln_ab_eval
SPEC.loader.exec_module(web2_vuln_ab_eval)


def test_web2_vuln_ab_cases_keep_current_method_signal_coverage():
    result = web2_vuln_ab_eval.evaluate_cases(REPO_ROOT)
    summary = result["summary"]

    assert summary["case_count"] >= 10
    method = REPO_ROOT / "knowledge/playbooks/web2-evidence-contracts.md"
    assert summary["method_path"] == method.relative_to(REPO_ROOT).as_posix()
    assert summary["method_lines"] == len(method.read_text(encoding="utf-8").splitlines()) > 0
    assert summary["method_sha256"] == hashlib.sha256(method.read_bytes()).hexdigest()
    assert result["diagnostic"]["kind"] == "current-source-offline-signals"
    assert summary["enhanced_total"] >= summary["baseline_total"]
    assert summary["enhanced_total"] == summary["max_total"]
    assert not summary["cases_missing_even_enhanced"]
    assert not summary["route_gap_cases"]
    # S1 native loading (batch 3): the pack's skill recommendation slot is
    # removed; this eval scores card/signal recall quality, which is unchanged.
    # Rows carry no skill value, and the retired field is gone entirely.
    assert all("selected_skill" not in row for row in result["rows"])
    assert all(summary["method_path"] in row["enhanced_paths"] for row in result["rows"])
    assert all("skills/web2-vuln-classes/SKILL.md" not in row["enhanced_paths"] for row in result["rows"])


def test_web2_vuln_ab_report_mentions_interpretation():
    result = web2_vuln_ab_eval.evaluate_cases(REPO_ROOT)
    report = web2_vuln_ab_eval.format_markdown(result)

    assert "Current-source offline signal diagnostic" in report
    assert "does not rerun the historical Skill A/B" in report
    assert "do not prove model discovery, selection, or reasoning quality" in report
    assert result["summary"]["method_path"] in report
    assert result["summary"]["method_sha256"] in report
    assert "| Case | Lane | Baseline |" in report
    # The retired skill slot no longer publishes a report column.
    assert "Selected Skill" not in report


@pytest.mark.parametrize("contents", [None, "", " \n"])
def test_web2_diagnostic_rejects_missing_or_empty_method(tmp_path, contents):
    method = tmp_path / "knowledge/playbooks/web2-evidence-contracts.md"
    if contents is not None:
        method.parent.mkdir(parents=True)
        method.write_text(contents, encoding="utf-8")
    with pytest.raises(FileNotFoundError if contents is None else ValueError, match="web2-evidence-contracts"):
        web2_vuln_ab_eval.evaluate_cases(tmp_path)
