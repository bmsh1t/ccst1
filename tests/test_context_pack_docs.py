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


def test_context_pack_keeps_advisory_selection_boundary():
    text = _read("commands/context-pack.md")

    assert "AI override" in text
    assert "兼容推荐字段" in text
    assert "Claude 根据当前证据显式选择" in text
    assert "首次选择不是 override" in text
    assert "必须说明选择原因" in text
    assert "工具推荐不是强制路线" in text


def test_shared_recall_gate_is_shared_by_prompt_and_autopilot_entries():
    shared_path = "skills/runtime-protocol.md"
    reference = f"{shared_path}#shared-knowledge-recall"

    assert "## Shared Knowledge Recall" in _read(shared_path)
    for entry in (
        "CLAUDE.md",
        "skills/web2-vuln-classes/SKILL.md",
        "commands/autopilot.md",
        "commands/hunt.md",
        "commands/context-pack.md",
    ):
        assert reference in _read(entry), entry
    autopilot = _read("commands/autopilot.md")
    assert "checkpoint is" in autopilot and "mandatory before claim" in autopilot
    assert "Target memory alone is not a Context Pack" in autopilot


def test_shared_recall_and_web2_skill_do_not_duplicate_card_maps():
    for entry in ("skills/runtime-protocol.md", "skills/web2-vuln-classes/SKILL.md"):
        assert "knowledge/cards/" not in _read(entry), entry
