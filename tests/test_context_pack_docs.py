"""Regression tests for /context-pack command documentation."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_context_pack_command_uses_tool_not_manual_prompt_only():
    text = _read("commands/context-pack.md")

    assert "python3 tools/context_pack.py --target <target>" in text
    assert "surface 排名" in text
    assert "覆盖矩阵" in text
    assert "findings/<target>/findings.json" in text
    assert "recon/<target>/browser/xhr_endpoints.txt" in text
    assert "findings/<target>/js_intel/hypotheses.json" in text
    assert "findings/<target>/source_intel/hypotheses.jsonl" in text
    assert "memory/evidence/<target>/ledger.jsonl" in text
    assert "Actor matrix gaps" in text
    assert "raw browser capture requests/console/storage" in text
    assert "不执行测试、不扫描目标、不写目标记忆" in text


def test_context_pack_keeps_ai_override_boundary():
    text = _read("commands/context-pack.md")

    assert "AI override" in text
    assert "Claude 可以改选" in text
    assert "必须说明原因" in text
    assert "工具推荐不是强制路线" in text
