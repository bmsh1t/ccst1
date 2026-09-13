"""knowledge_promote: mv + 登记 + 端到端验收（晋升断点的修复锁）。

记忆复核确认的断点：46462a5 修通来源解析后，`mv` 仍不等于完成晋升——
registry 目录不含未登记卡（Pack 不可见），audit 的 document-unregistered
是硬错误。本工具一条命令完成 mv、registry 追加、strict audit、目录可发现
四步，失败原子回滚。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from knowledge_promote import promote


def _seed_candidate(repo: Path, card_id: str = "t-cross-actor") -> None:
    candidates = repo / "knowledge" / "candidates"
    cards = repo / "knowledge" / "cards"
    candidates.mkdir(parents=True, exist_ok=True)
    cards.mkdir(parents=True, exist_ok=True)
    probe = repo / "evidence" / "t.example" / "probe"
    probe.mkdir(parents=True, exist_ok=True)
    (probe / "p1.json").write_text("{}", encoding="utf-8")
    ref = "evidence/t.example/probe/p1.json"
    # audit 要求 related_skills 指向真实存在的 skill 文件
    skill = repo / "skills" / "web2-vuln-classes"
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text("---\nname: web2-vuln-classes\n---\n", encoding="utf-8")
    (candidates / f"{card_id}.md").write_text(f"""---
id: {card_id}
type: technique-card
related_skills:
  - web2-vuln-classes
trigger_tags:
  - {card_id}
risk: low
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: target-evidence
    target: t.example
    refs:
      - "{ref}"
updated: 2026-09-12
---

# 测试候选卡

## Quick Recall

- 触发：trigger text
- 判定条件：cond text
- 停止：stop text

## 触发信号

- trigger text

## 思路分支 / 最小验证

- action text

## 证据

- 来源目标：t.example（脱敏后写入）

## 常见误判 / 死路

- misjudge text

## 下一步或晋升

- next text
""", encoding="utf-8")
    # registry 模板（满足 audit 的 contracts 契约）
    (repo / "knowledge" / "capabilities.yaml").write_text(
        "schema_version: 1\ncontracts:\n"
        "  max_core_cards: 20\n  default_cards_max: 8\n"
        "  card_layers:\n    - core\n    - reference\n    - case-router\n    - payload-pack\n    - playbook\n"
        "  load_modes:\n    - default\n    - signal-or-default\n    - signal-only\n    - on-demand\n    - gated\n"
        "capabilities: []\n",
        encoding="utf-8",
    )


def test_promote_moves_registers_and_passes_audit(tmp_path):
    _seed_candidate(tmp_path)
    result = promote(tmp_path, card_id="t-cross-actor", triggers=["idor", "cross-actor"])
    assert result["promoted"] == "t-cross-actor"
    assert result["audit"] == "strict-pass"
    assert result["catalog_discoverable"] is True
    # 文件移动
    assert not (tmp_path / "knowledge" / "candidates" / "t-cross-actor.md").exists()
    assert (tmp_path / "knowledge" / "cards" / "t-cross-actor.md").is_file()
    # 登记条目
    yaml_text = (tmp_path / "knowledge" / "capabilities.yaml").read_text(encoding="utf-8")
    assert "id: t-cross-actor" in yaml_text and "knowledge/cards/t-cross-actor.md" in yaml_text


def test_promote_rolls_back_on_audit_failure(tmp_path):
    _seed_candidate(tmp_path)
    # 制造 audit 必败：registry 里预登记一个不存在的文件（registry-file-missing）
    p = tmp_path / "knowledge" / "capabilities.yaml"
    text = p.read_text(encoding="utf-8")
    import re

    match = re.search(r"(?ms)^capabilities:.*?(?=^\S|\Z)", text)
    broken_entry = (
        "  - id: ghost-card\n    kind: card\n    file: knowledge/cards/ghost-card.md\n"
        "    layer: case-router\n    load: on-demand\n    purpose: validate\n    triggers:\n      - ghost\n"
    )
    p.write_text(text[: match.start()] + "capabilities:\n" + broken_entry + text[match.end():], encoding="utf-8")
    try:
        promote(tmp_path, card_id="t-cross-actor")
    except SystemExit:
        pass
    else:
        raise AssertionError("expected audit failure to abort promote")
    # 原子回滚：候选仍在，cards 里没有，registry 恢复为原始内容（含预置 ghost）
    assert (tmp_path / "knowledge" / "candidates" / "t-cross-actor.md").is_file()
    assert not (tmp_path / "knowledge" / "cards" / "t-cross-actor.md").exists()
    yaml_text = p.read_text(encoding="utf-8")
    assert "ghost-card" in yaml_text  # 预置内容未被破坏
    assert "id: t-cross-actor" not in yaml_text  # promote 条目已回滚


def test_promote_rejects_missing_and_duplicate(tmp_path):
    _seed_candidate(tmp_path)
    try:
        promote(tmp_path, card_id="does-not-exist")
    except SystemExit as exc:
        assert "candidate not found" in str(exc)
    # 先成功 promote 一次，再重复应拒绝（目的地已存在即拒绝）
    promote(tmp_path, card_id="t-cross-actor")
    # 重新放一张同 id 候选（cards 里同名文件 + registry 已登记）
    (tmp_path / "knowledge" / "candidates" / "t-cross-actor.md").write_text("x", encoding="utf-8")
    try:
        promote(tmp_path, card_id="t-cross-actor")
    except SystemExit as exc:
        assert "already exists" in str(exc) or "already registered" in str(exc)
    else:
        raise AssertionError("expected duplicate rejection")


def test_promoted_card_is_pack_catalog_discoverable(tmp_path):
    """端到端验收：晋升后的卡必须出现在 Pack 的卡片目录里（复核点 2）。

    子进程必须能加载真实的 context_pack（repo 的 tools/ 在 sys.path）；
    失败即失败——旧版在非零返回时降级为只查 registry，实际是
    ModuleNotFoundError 假绿，保护不了真实加载链。
    """
    import subprocess

    _seed_candidate(tmp_path)
    promote(tmp_path, card_id="t-cross-actor")
    tools_dir = Path(__file__).resolve().parent.parent / "tools"
    code = (
        "import sys; sys.path.insert(0, " + repr(str(tools_dir)) + ")\n"
        "import context_pack\n"
        "cat = context_pack._card_catalog('" + str(tmp_path) + "')\n"
        "ids = [row.get('id') for row in (cat if isinstance(cat, list) else cat.get('cards', []))]\n"
        "assert 't-cross-actor' in ids, ids\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 0, f"pack catalog subprocess failed:\n{result.stderr}"
    assert "ok" in result.stdout


def test_promote_rolls_back_on_registry_write_failure(tmp_path, monkeypatch):
    """故障注入：registry 原子写抛 OSError 时，candidate 与 registry 必须复原。"""
    import knowledge_promote

    _seed_candidate(tmp_path)
    original = knowledge_promote._atomic_write_text
    calls = {"n": 0}

    def fail_first_write(path, content):
        # 只让 registry 的追加写失败；回滚自身也要能写。
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("injected registry write failure")
        return original(path, content)

    monkeypatch.setattr(knowledge_promote, "_atomic_write_text", fail_first_write)
    try:
        promote(tmp_path, card_id="t-cross-actor")
    except SystemExit as exc:
        assert "registry append failed" in str(exc)
    else:
        raise AssertionError("expected registry write failure to abort promote")

    # 复原：候选仍在，cards 无新卡，registry 无 promote 条目
    assert (tmp_path / "knowledge" / "candidates" / "t-cross-actor.md").is_file()
    assert not (tmp_path / "knowledge" / "cards" / "t-cross-actor.md").exists()
    yaml_text = (tmp_path / "knowledge" / "capabilities.yaml").read_text(encoding="utf-8")
    assert "id: t-cross-actor" not in yaml_text


def test_promote_rolls_back_on_audit_process_start_failure(tmp_path, monkeypatch):
    """故障注入：audit 子进程启动失败时，candidate 与 registry 必须复原。"""
    import knowledge_promote

    _seed_candidate(tmp_path)
    registry_before = (tmp_path / "knowledge" / "capabilities.yaml").read_text(encoding="utf-8")

    def fail_run(*args, **kwargs):
        raise OSError("injected subprocess launch failure")

    monkeypatch.setattr(knowledge_promote.subprocess, "run", fail_run)
    try:
        promote(tmp_path, card_id="t-cross-actor")
    except SystemExit as exc:
        assert "audit process failed to start" in str(exc)
    else:
        raise AssertionError("expected audit launch failure to abort promote")

    # 复原：候选仍在，cards 无新卡，registry 逐字节恢复
    assert (tmp_path / "knowledge" / "candidates" / "t-cross-actor.md").is_file()
    assert not (tmp_path / "knowledge" / "cards" / "t-cross-actor.md").exists()
    assert (tmp_path / "knowledge" / "capabilities.yaml").read_text(encoding="utf-8") == registry_before
