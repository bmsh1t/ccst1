"""Structural tests for agents/web3-auditor.md.

Per task 05-16-b5 (R2, R4): tests check structural invariants — frontmatter,
model allow-list, tool subset, body length, description style, web3 bug-class
coverage, and Foundry PoC template reference. NO assertion on specific
prompt-string content.
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

SLUG = "web3-auditor"


@pytest.fixture(scope="module")
def text() -> str:
    return read_agent(SLUG)


@pytest.fixture(scope="module")
def fm(text: str) -> dict:
    return parse_frontmatter(text)


def test_agent_file_exists():
    """agents/web3-auditor.md must exist on disk."""
    p = agent_path(SLUG)
    assert p.is_file(), f"{p} not found"


def test_frontmatter_has_required_keys(fm: dict):
    assert_required_frontmatter_keys(fm)


def test_name_matches_file_slug(fm: dict):
    assert_name_matches_slug(fm, SLUG)


def test_model_is_in_allow_list(fm: dict):
    assert_model_is_allowed(fm)


def test_tools_subset_of_canonical_set(fm: dict):
    assert_tools_subset(fm)


def test_body_length_within_bounds(text: str):
    assert_body_length(text, min_chars=300, max_chars=8000)


def test_description_starts_with_present_tense_verb(fm: dict):
    assert_description_style(fm)


def test_body_references_ten_canonical_web3_classes(text: str):
    """Body must reference the 10 canonical web3 bug classes (per B5 R2).

    Counted by `### Class N:` headers — the audit agent enumerates its
    protocol explicitly. Allow 10..12 in case operator extends safely.
    """
    body = text.split("---", 2)[-1]
    class_headers = [
        line for line in body.splitlines()
        if line.strip().startswith("### Class ")
    ]
    assert 10 <= len(class_headers) <= 12, (
        f"expected 10..12 web3 bug-class headers, found {len(class_headers)}: "
        f"{[h.strip() for h in class_headers]}"
    )


def test_body_references_foundry_poc(text: str):
    """Body must reference the Foundry PoC template (per B5 R2 final bullet)."""
    assert_body_references_any(
        text,
        ["FOUNDRY POC", "Foundry POC", "Foundry PoC", "foundry", "Foundry"],
    )


def test_body_references_canonical_audit_classes(text: str):
    """Spot-check: at least 3 of the canonical class names appear (R2 R bullet)."""
    canonical = [
        "Accounting Desync",
        "Access Control",
        "Incomplete Code Path",
        "Off-By-One",
        "Oracle",
        "ERC4626",
        "Reentrancy",
        "Flash Loan",
        "Signature Replay",
        "Proxy",
    ]
    body = text.split("---", 2)[-1]
    hits = [c for c in canonical if c in body]
    assert len(hits) >= 3, (
        f"expected >=3 canonical bug-class names in body, found {len(hits)}: {hits}"
    )


def test_frontmatter_error_message_names_field():
    """AgentDocError on missing required key must name that field."""
    bad_fm = {"name": "web3-auditor", "description": "Audits", "model": "inherit"}
    # missing `tools` — error must say so
    with pytest.raises(AgentDocError) as exc:
        assert_required_frontmatter_keys(bad_fm)
    assert "tools" in str(exc.value), (
        f"error message did not mention the missing field 'tools': {exc.value}"
    )
