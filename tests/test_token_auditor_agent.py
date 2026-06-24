"""Structural tests for agents/token-auditor.md.

Per task 05-16-b5 (R1, R4): tests check structural invariants of the agent .md
file — frontmatter completeness, model allow-list, tool subset, body length,
description style, and tool reference. NO assertion is made on specific
prompt-string content.

Future small changes to agents/token-auditor.md (adding trailing comments,
extending audit classes) MUST NOT break these tests; if they do, the failing
assert is intended to point at the precise field that broke.
"""

import pytest

from tests._agent_test_helpers import (
    AgentDocError,
    agent_path,
    assert_body_length,
    assert_body_references_any,
    assert_description_style,
    assert_model_is_allowed,
    assert_name_matches_slug,
    assert_required_frontmatter_keys,
    assert_tools_subset,
    parse_frontmatter,
    read_agent,
)

SLUG = "token-auditor"


@pytest.fixture(scope="module")
def text() -> str:
    return read_agent(SLUG)


@pytest.fixture(scope="module")
def fm(text: str) -> dict:
    return parse_frontmatter(text)


def test_agent_file_exists():
    """agents/token-auditor.md must exist on disk."""
    p = agent_path(SLUG)
    assert p.is_file(), f"{p} not found"


def test_frontmatter_has_required_keys(fm: dict):
    """frontmatter must contain name, description, tools, model."""
    assert_required_frontmatter_keys(fm)


def test_name_matches_file_slug(fm: dict):
    """frontmatter `name` must equal the file slug `token-auditor`."""
    assert_name_matches_slug(fm, SLUG)


def test_model_is_in_allow_list(fm: dict):
    """`model` must be one of {inherit, sonnet, opus, haiku}."""
    assert_model_is_allowed(fm)


def test_tools_subset_of_canonical_set(fm: dict):
    """All declared tools must be in the canonical Claude Code agent tool set."""
    assert_tools_subset(fm)


def test_body_length_within_bounds(text: str):
    """Body must be 300..8000 chars (no truncation, no prompt bloat)."""
    assert_body_length(text, min_chars=300, max_chars=8000)


def test_description_starts_with_present_tense_verb(fm: dict):
    """First word of description must be in PRESENT_TENSE_VERB_ALLOW (soft check)."""
    assert_description_style(fm)


def test_body_references_token_scanner_tool(text: str):
    """Body must reference at least one repo tool (per B5 R1 — token_scanner.py)."""
    assert_body_references_any(
        text,
        ["tools/token_scanner.py", "token_scanner.py"],
    )


def test_body_references_solana_and_evm_chains(text: str):
    """token-auditor explicitly covers both EVM and Solana — body should mention both.

    This is a structural invariant (chain-agnostic auditor MUST mention both
    chains in its prompt), not a prompt-string assertion on wording.
    """
    body = text.split("---", 2)[-1]
    assert "EVM" in body or "Solidity" in body, "body must mention EVM/Solidity chain"
    assert "Solana" in body or "Rust" in body, "body must mention Solana/Rust chain"


def test_frontmatter_error_messages_point_at_field():
    """If frontmatter is malformed, the AgentDocError must name the broken field
    (per B5 final AC bullet)."""
    bad_fm = {"name": "token-auditor", "description": "Audits stuff", "tools": ["Bash"]}
    # missing `model` — error must say so
    with pytest.raises(AgentDocError) as exc:
        assert_required_frontmatter_keys(bad_fm)
    assert "model" in str(exc.value), (
        f"error message did not mention the missing field 'model': {exc.value}"
    )
