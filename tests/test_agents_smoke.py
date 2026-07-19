"""Smoke test: structural invariants across ALL agents in agents/.

Proves that `tests/_agent_test_helpers.py` is general — not specific to
token-auditor or web3-auditor (per B5 R3 / final AC bullet about helper
generality).

Per B5 NG1: this does NOT replace per-agent tests for the other 8 agents (those
already have ≥1 existing test mention each per audit R5). It is a smoke gate:
if frontmatter parsing breaks on any single agent .md, this surfaces it.
"""

from __future__ import annotations

import pytest

from tests._agent_test_helpers import (
    AGENTS_DIR,
    assert_model_is_allowed,
    assert_required_frontmatter_keys,
    assert_tools_subset,
    parse_frontmatter,
)


def _list_agent_md_files() -> list[str]:
    files = sorted(
        p.name
        for p in AGENTS_DIR.glob("*.md")
        if not p.name.lower().endswith(".patch.md")
    )
    return files


AGENT_FILES = _list_agent_md_files()


def test_agents_dir_not_empty():
    assert AGENT_FILES, f"no .md files found in {AGENTS_DIR}"


@pytest.mark.parametrize("filename", AGENT_FILES)
def test_every_agent_has_parseable_frontmatter(filename: str):
    """Every agent .md must have parseable frontmatter."""
    text = (AGENTS_DIR / filename).read_text(encoding="utf-8")
    fm = parse_frontmatter(text)
    assert "name" in fm, f"{filename}: no name in frontmatter"


@pytest.mark.parametrize("filename", AGENT_FILES)
def test_every_agent_has_required_keys(filename: str):
    """Every agent .md frontmatter must have {name, description, tools, model}."""
    text = (AGENTS_DIR / filename).read_text(encoding="utf-8")
    fm = parse_frontmatter(text)
    assert_required_frontmatter_keys(fm)


@pytest.mark.parametrize("filename", AGENT_FILES)
def test_every_agent_model_is_allow_listed(filename: str):
    """Every agent's `model` field must be in {inherit, sonnet, opus, haiku}."""
    text = (AGENTS_DIR / filename).read_text(encoding="utf-8")
    fm = parse_frontmatter(text)
    assert_model_is_allowed(fm)


@pytest.mark.parametrize("filename", AGENT_FILES)
def test_every_agent_tools_subset(filename: str):
    """Every agent's `tools` field must be a subset of the canonical tool set."""
    text = (AGENTS_DIR / filename).read_text(encoding="utf-8")
    fm = parse_frontmatter(text)
    assert_tools_subset(fm)
