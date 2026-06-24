"""Regression tests for Evidence Ledger command documentation."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_evidence_ledger_command_documents_summary_and_record():
    text = _read("commands/evidence-ledger.md")

    assert "python3 tools/evidence_ledger.py summary --target <target>" in text
    assert "python3 tools/evidence_ledger.py record" in text
    assert "memory/evidence/<target>/ledger.jsonl" in text
    assert "Actor Matrix" in text
    assert "rules/red-lines.md" in text


def test_checkpoint_reads_evidence_ledger_before_handoff():
    text = _read("commands/checkpoint.md")

    assert "python3 tools/evidence_ledger.py summary --target <target>" in text
    assert "Evidence Ledger 摘要和 Actor Matrix gaps" in text
    assert "coverage gap 为空但 Actor Matrix 仍有缺口" in text
