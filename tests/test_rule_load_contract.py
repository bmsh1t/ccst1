"""Regression tests for Rule loading and ownership boundaries."""

from pathlib import Path

import context_pack


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_default_context_pack_keeps_hunting_rule_on_demand():
    checks = context_pack._required_checks("skills/web2-recon/SKILL.md", "recon")

    assert checks == [
        "rules/context-loading.md",
        "rules/red-lines.md",
        "rules/coverage-gate.md",
    ]
    assert "rules/hunting.md" not in checks
    assert "rules/tool-ai-boundary.md" not in checks


def test_hunting_entrypoints_explicitly_load_canonical_rule():
    assert "canonical hunting semantics" in _read("rules/hunting.md")
    assert "read `rules/hunting.md`" in _read("commands/hunt.md")
    assert "load `rules/hunting.md`" in _read("commands/autopilot.md")
    assert "按需加载 `rules/hunting.md`" in _read("skills/bb-methodology/SKILL.md")


def test_rule_index_covers_every_rule_with_one_owner():
    index = _read("rules/README.md")
    rule_files = sorted(path.name for path in (REPO_ROOT / "rules").glob("*.md") if path.name != "README.md")
    owner_rows = [line for line in index.splitlines() if line.startswith("| `")]

    assert all(f"`{name}`" in index for name in rule_files)
    assert len(owner_rows) == len(rule_files)
