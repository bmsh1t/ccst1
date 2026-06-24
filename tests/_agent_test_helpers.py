"""Shared helpers for agent .md frontmatter / structure tests.

Used by `tests/test_token_auditor_agent.py`, `tests/test_web3_auditor_agent.py`,
and any future agent .md test that needs frontmatter parsing.

Per task 05-16-b5 (R3): if a frontmatter helper already exists in tests/, reuse
it; otherwise create this small shared module so future agent tests share the
same parser.

Per R4: tests built on this helper MUST NOT assert on specific prompt-string
content — only on structural invariants.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / "agents"

# Canonical Claude Code agent tool set. New tools added to .claude must
# also be added here, or agent tests will (correctly) start failing.
CANONICAL_AGENT_TOOLS: set[str] = {
    "Bash",
    "Read",
    "Write",
    "Edit",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "Task",
    "TodoWrite",
    "NotebookEdit",
}

# Canonical agent.md frontmatter keys. `name`, `description`, `tools`, `model`
# are all required (per B5 R1/R2). Other keys are allowed but currently
# unused.
REQUIRED_FRONTMATTER_KEYS: set[str] = {"name", "description", "tools", "model"}

# Allowed `model:` values in agent frontmatter.
ALLOWED_MODELS: set[str] = {"inherit", "sonnet", "opus", "haiku"}

# Present-tense verb allow-list for agent description first word.
# Soft check per B5 R1 — extend as new agents land.
PRESENT_TENSE_VERB_ALLOW: set[str] = {
    "Performs",
    "Performs,",
    "Audits",
    "Generates",
    "Reads",
    "Reads,",
    "Runs",
    "Checks",
    "Builds",
    "Identifies",
    "Validates",
    "Fast",  # legacy: "Fast meme coin and token security auditor"
    "Subdomain",  # legacy: "Subdomain enumeration and live host discovery specialist"
    "Smart",  # legacy: "Smart contract security auditor"
    "Penetration",  # legacy: "Penetration-testing report writer"
    "JS",  # legacy: "JS static reader"
    "Exploit",  # legacy: "Exploit chain builder"
    "Finding",  # legacy: "Finding validator"
    "Attack",  # legacy: "Attack surface ranking agent"
    "Autonomous",  # legacy: "Autonomous hunt loop agent"
    "Catch-all",  # legacy: "Catch-all for any task..."
}


class AgentDocError(AssertionError):
    """Raised by helpers when a structural invariant is violated."""


def agent_path(slug: str) -> Path:
    """Return absolute path to the agent .md file for `slug`."""
    return AGENTS_DIR / f"{slug}.md"


def read_agent(slug: str) -> str:
    """Read the full text of agent .md `slug`. Raises FileNotFoundError if missing."""
    return agent_path(slug).read_text(encoding="utf-8")


# Frontmatter parsing intentionally avoids PyYAML — stdlib only per B5 C2.
# We support the YAML subset the project actually uses: scalar values,
# multi-line scalars via `>-`, and inline / multi-line bracketed lists.

_FRONTMATTER_RE = re.compile(
    r"\A---\n(?P<body>.*?)\n---\n",
    re.DOTALL,
)


def split_frontmatter(text: str) -> tuple[str, str]:
    """Return (frontmatter_text, body_text). Raises AgentDocError if the file
    does not start with `---` ... `---` block."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        raise AgentDocError(
            "agent file missing YAML frontmatter (`---` ... `---`)"
        )
    body_start = m.end()
    return m.group("body"), text[body_start:]


def _normalize_value(raw: str) -> Any:
    s = raw.strip()
    if not s:
        return ""
    # bracketed inline list: "[A, B, C]"
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [item.strip().strip("\"'") for item in inner.split(",")]
    # quoted scalar
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def parse_frontmatter(text: str) -> dict[str, Any]:
    """Parse the YAML-subset frontmatter used by repo agent .md files.

    Supports:
      - `key: value` scalar
      - `key: >- ... continuation lines ...` folded scalar
      - `tools: A, B, C` comma-separated list (returned as list[str])
      - `tools: [A, B, C]` bracketed inline list

    Does NOT support nested mappings, anchors, or full YAML — by design (C2).
    """
    fm_text, _ = split_frontmatter(text)
    out: dict[str, Any] = {}
    lines = fm_text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if ":" not in line:
            i += 1
            continue
        key, _, raw = line.partition(":")
        key = key.strip()
        raw = raw.strip()

        if raw == ">-" or raw == ">":
            # folded scalar: collect indented continuation lines
            parts: list[str] = []
            i += 1
            while i < len(lines) and (lines[i].startswith("  ") or lines[i] == ""):
                if lines[i] == "":
                    i += 1
                    continue
                parts.append(lines[i].strip())
                i += 1
            out[key] = " ".join(parts)
            continue

        if key == "tools" and raw and not raw.startswith("["):
            # comma-separated list without brackets
            out[key] = [item.strip() for item in raw.split(",") if item.strip()]
            i += 1
            continue

        out[key] = _normalize_value(raw)
        i += 1

    return out


def assert_required_frontmatter_keys(fm: dict[str, Any]) -> None:
    """Raise AgentDocError if any of {name, description, tools, model} missing."""
    missing = REQUIRED_FRONTMATTER_KEYS - set(fm.keys())
    if missing:
        raise AgentDocError(
            f"frontmatter missing required keys: {sorted(missing)}; "
            f"present={sorted(fm.keys())}"
        )


def assert_model_is_allowed(fm: dict[str, Any]) -> None:
    """Raise AgentDocError if `model` is not in {inherit, sonnet, opus, haiku}."""
    model = fm.get("model", "")
    if model not in ALLOWED_MODELS:
        raise AgentDocError(
            f"model={model!r} not in allowed set {sorted(ALLOWED_MODELS)}"
        )


def assert_tools_subset(fm: dict[str, Any]) -> None:
    """Raise AgentDocError if any tool is not in CANONICAL_AGENT_TOOLS."""
    tools = fm.get("tools", [])
    if not isinstance(tools, list):
        raise AgentDocError(
            f"tools must be a list, got {type(tools).__name__}: {tools!r}"
        )
    unknown = [t for t in tools if t not in CANONICAL_AGENT_TOOLS]
    if unknown:
        raise AgentDocError(
            f"tools contains values outside canonical set: {unknown}; "
            f"allowed={sorted(CANONICAL_AGENT_TOOLS)}"
        )


def assert_name_matches_slug(fm: dict[str, Any], slug: str) -> None:
    """Raise AgentDocError if frontmatter `name` does not equal file slug."""
    name = fm.get("name", "")
    if name != slug:
        raise AgentDocError(
            f"frontmatter name={name!r} does not match file slug {slug!r}"
        )


def assert_body_length(text: str, *, min_chars: int = 300, max_chars: int = 8000) -> None:
    """Raise AgentDocError if body length is outside [min_chars, max_chars]."""
    _, body = split_frontmatter(text)
    n = len(body)
    if n < min_chars:
        raise AgentDocError(
            f"agent body is {n} chars, below minimum {min_chars} "
            "(probably truncated)"
        )
    if n > max_chars:
        raise AgentDocError(
            f"agent body is {n} chars, above maximum {max_chars} "
            "(probably prompt bloat)"
        )


def assert_description_style(fm: dict[str, Any]) -> None:
    """Soft check: description starts with a present-tense verb allow-listed
    in PRESENT_TENSE_VERB_ALLOW. Raises AgentDocError on miss so the test
    points at the field that broke (per B5 final AC bullet)."""
    desc = (fm.get("description") or "").strip()
    if not desc:
        raise AgentDocError("description is empty")
    first_word = desc.split()[0]
    if first_word not in PRESENT_TENSE_VERB_ALLOW:
        raise AgentDocError(
            f"description first word {first_word!r} not in allow-list; "
            "add it to PRESENT_TENSE_VERB_ALLOW in _agent_test_helpers.py "
            "if it is intentionally present-tense"
        )


def assert_body_references_any(text: str, candidates: list[str]) -> None:
    """Raise AgentDocError if the body does NOT mention any string in `candidates`.

    Used to assert that an agent references at least one repo tool (B5 R1) or
    a canonical pattern set (B5 R2).
    """
    _, body = split_frontmatter(text)
    matches = [c for c in candidates if c in body]
    if not matches:
        raise AgentDocError(
            f"agent body does not reference any of: {candidates}"
        )


__all__ = [
    "AgentDocError",
    "AGENTS_DIR",
    "ALLOWED_MODELS",
    "CANONICAL_AGENT_TOOLS",
    "PRESENT_TENSE_VERB_ALLOW",
    "REQUIRED_FRONTMATTER_KEYS",
    "REPO_ROOT",
    "agent_path",
    "read_agent",
    "split_frontmatter",
    "parse_frontmatter",
    "assert_required_frontmatter_keys",
    "assert_model_is_allowed",
    "assert_tools_subset",
    "assert_name_matches_slug",
    "assert_body_length",
    "assert_description_style",
    "assert_body_references_any",
]
