"""Regression tests for Rule loading and ownership boundaries."""

from pathlib import Path

import context_pack
from tools.context_pack import build_context_pack


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_default_context_pack_keeps_hunting_rule_on_demand():
    checks = context_pack._required_checks("skills/web2-recon/SKILL.md", "recon")

    assert checks == [
        "rules/coverage-gate.md",
    ]
    assert "rules/hunting.md" not in checks
    assert "rules/tool-ai-boundary.md" not in checks


def test_hunting_entrypoints_explicitly_load_canonical_rule():
    assert "canonical hunting semantics" in _read("rules/hunting.md")
    assert "read `rules/hunting.md`" in _read("commands/hunt.md")
    assert "load `rules/hunting.md`" in _read("commands/autopilot.md")
    assert "按需加载 `rules/hunting.md`" in _read("skills/bb-methodology/SKILL.md")


def test_context_pack_defers_knowledge_catalog_and_keeps_structural_router_on_demand(tmp_path):
    ordinary = build_context_pack(tmp_path, target="target.test", focus="ssrf api testing xss")
    structural = build_context_pack(
        tmp_path,
        target="target.test",
        focus="proxy parser normalization unicode truncation WAF differential",
    )

    assert "knowledge/index.md" not in ordinary["must_read"]
    assert "rules/playbook-router.md" not in ordinary["required_checks"]
    assert "rules/playbook-router.md" in structural["required_checks"]


def test_hunting_guidance_is_event_driven_not_a_fixed_clock_or_probe_order():
    methodology = _read("skills/bb-methodology/SKILL.md")
    hunting = _read("rules/hunting.md")

    assert "progress fingerprint" in methodology
    assert "not a\nmandatory sequence" in methodology
    assert "progress fingerprint" in hunting
    assert "5-minute rule" not in methodology.lower()
    assert "20-minute rotation clock" not in methodology.lower()


def test_rule_index_covers_every_rule_with_one_owner():
    index = _read("rules/README.md")
    rule_files = sorted(path.name for path in (REPO_ROOT / "rules").glob("*.md") if path.name != "README.md")
    owner_rows = [line for line in index.splitlines() if line.startswith("| `")]

    assert all(f"`{name}`" in index for name in rule_files)
    assert len(owner_rows) == len(rule_files)
    assert "| `tool-ai-boundary.md` | `rules/tool-ai-boundary.md` |" in index
