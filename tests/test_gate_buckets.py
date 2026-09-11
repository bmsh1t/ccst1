"""Gate bucket discipline regression tests (P0, task 09-11-ai-capability-roadmap).

This file encodes the trust-framework bucket discipline as a permanent
regression asset: every mechanical gate (``raise ValueError`` /
``raise RuntimeError``) in the owner tools must belong to exactly one of
four buckets --

- ``DANGER``           (危险操作桶)  secrets, target scope, red-line discipline.
- ``REPORT``           (报告标准桶)  evidence / report / completion standards.
- ``BOUNDED_FAILSAFE`` (失控边界)    budgets, caps and runaway bounds.
- ``FORMAT``           (显式格式类)  declared format / contract validation.

A gate that fits none of these buckets is a *content-level gate*: it would
substitute the framework's judgment for the AI's judgment about *what* to
test (for example "refuses SQLi family without prior XSS coverage") and
violates the "free the AI's thinking" principle this roadmap protects.

Negative verification (implement.md step 0.3): if a content-level gate is
injected into an owner tool, e.g.::

    raise ValueError(
        "Action Queue refuses SQLi family without prior XSS coverage"
    )

then ``test_owner_gate_raises_are_bucketed`` must fail. The companion test
``test_bucket_registry_rejects_content_gate`` proves the defense works
without modifying any ``tools/`` source, and
``test_injected_content_gate_in_source_is_unbucketed`` proves it end to end
against a temporary source file.

Known limitation (stated honestly): the pattern net guarantees that the
current corpus is fully classified and that known content-gate message
shapes (vulnerability class / family / technique routing preconditions)
are rejected. It cannot prove the absence of every conceivable content
gate phrased only with whitelisted format vocabulary; new gates still get
reviewed because this test turns red whenever their message does not fit
a bucket.

This test is intentionally read-only with respect to ``tools/``: sources
are parsed with ``ast`` (no imports, no execution) and never mutated.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

OWNER_SOURCES = (
    REPO_ROOT / "tools" / "action_queue.py",
    REPO_ROOT / "tools" / "validation_runner.py",
    REPO_ROOT / "tools" / "validate.py",
    REPO_ROOT / "tools" / "checkpoint.py",
)

# Minimum classifiable-gate counts per source. The floors exist so that a
# broken extractor, a moved owner file, or a wholesale refactor fails loudly
# instead of letting the bucket assertion pass vacuously on an empty corpus.
# Current baseline: action_queue 52 / validation_runner 10 / validate 62 /
# checkpoint 23 ValueError gates.
MIN_GATES_PER_SOURCE = {
    "action_queue.py": 30,
    "validation_runner.py": 5,
    "validate.py": 40,
    "checkpoint.py": 15,
}

# ---------------------------------------------------------------------------
# Bucket registry
# ---------------------------------------------------------------------------
# Patterns are matched case-insensitively with ``re.search`` in priority
# order: DANGER, then CONTENT_GATE rejection, then REPORT, then
# BOUNDED_FAILSAFE, then FORMAT. A message matching several buckets is
# assigned to the strictest one (e.g. a scope gate that also mentions a
# vulnerability class stays DANGER; a cap message that also says "must be"
# stays BOUNDED_FAILSAFE).

DANGER_PATTERNS = [
    # Secrets must never enter owner records.
    r"sensitive field",
    r"credential or header values",
    # Requests, responses and redirects must stay inside target scope.
    r"outside target scope",
    r"left target scope",
    r"off-target",
    # Side-effect discipline (rules/red-lines.md).
    r"redline",
    r"red-line",
    r"state-changing",
]

REPORT_PATTERNS = [
    # Design baseline (实测 41-way split).
    r"replayable",
    r"evidence[._ ]?refs?",
    r"baseline",
    r"observed difference",
    r"lead.*candidate.*wrap",
    # Evidence / report artifacts and cross-record consistency.
    r"runner[_ ]summary",
    r"canonical finding",
    r"witness",
    r"artifact",
    r"queue changed",
    r"operation material",
    r"evidence reference",
    r"evidence must be",
    r"does not match",
    # Completion-claim discipline (anti pretend-tested, anti premature close).
    r"tested_dimensions",
    r"exactly one continuation",
    r"non-empty basis",
    r"invalid completed lane evidence",
    r"unfinished lanes",
    r"global review",
    r"cannot be rewritten",
    r"owned by another finding",
]

BOUNDED_FAILSAFE_PATTERNS = [
    # Runaway bounds: hypothesis/action budgets, capability caps, size and
    # length limits (字数上限 per the design note).
    r"budget",
    r"exhausted",
    r"\bcap\b",
    r"\bmax[_-][a-z_]+\b",
    r"at most",
    r"exceeds",
]

FORMAT_PATTERNS = [
    # Declared whitelist of format / contract validation vocabulary.
    r"must be",
    r"must contain",
    r"must stay",
    r"must match",
    r"must exactly match",
    r"must reference",
    r"requires",
    r"is required",
    r"invalid",
    r"cannot",
    r"lacks",
    r"refuses",
    r"accepts at most",
    r"unknown",
    r"missing",
    r"is not",
    r"not found",
    r"was not claimed",
    r"one line",
    r"positive integer",
    r"single-dimension",
    r"unable to read",
    r"unable to inspect",
    r"appeared during",
]

# Content-level gate rejection: messages that route *what* to test
# (vulnerability class / family / technique preconditions) instead of *how*
# the action or evidence is recorded. Checked after DANGER so scope and
# red-line gates always win even when they name a class.
CONTENT_GATE_PATTERNS = [
    r"\b(sqli|sql injection|xss|ssrf|idor|rce|csrf|xxe|ssti|lfi|rfi"
    r"|deseriali[sz]ation|path traversal|privilege escalat\w+)\b",
    r"\bvuln(erability)? class\b",  # prose "vuln class"; NOT the vuln_class field
    r"\bbug (class|family)\b",
    r"\battack (class|family|technique)\b",
    r"\bwithout prior\b",
    # Tightening (batch-0 check pass): these shapes routed WHAT to test while
    # slipping through FORMAT vocabulary. Verified zero false positives on
    # the current 147-gate corpus.
    r"\bfamily\b",
    r"\brequires prior\b",
    r"\bwithout (prior|completed|previous)\b",
]

BUCKETS_IN_PRIORITY_ORDER = (
    ("DANGER", DANGER_PATTERNS),
    ("REPORT", REPORT_PATTERNS),
    ("BOUNDED_FAILSAFE", BOUNDED_FAILSAFE_PATTERNS),
    ("FORMAT", FORMAT_PATTERNS),
)


def _matches_any(patterns: list[str], message: str) -> bool:
    return any(re.search(pattern, message, re.IGNORECASE) for pattern in patterns)


def classify_gate_message(message: str) -> str | None:
    """Return the bucket a gate message belongs to, or ``None`` when unbucketed.

    DANGER wins first; content-level gate shapes are then rejected
    (``None``); REPORT / BOUNDED_FAILSAFE / FORMAT follow in strictness
    order.
    """
    if _matches_any(DANGER_PATTERNS, message):
        return "DANGER"
    if _matches_any(CONTENT_GATE_PATTERNS, message):
        # A gate that routes WHAT to test is a content-level gate: it is
        # outside every bucket and must fail the discipline test.
        return None
    for bucket, patterns in BUCKETS_IN_PRIORITY_ORDER[1:]:
        if _matches_any(patterns, message):
            return bucket
    return None


# ---------------------------------------------------------------------------
# AST extraction
# ---------------------------------------------------------------------------

_DYNAMIC_PLACEHOLDER = "<dyn>"


@dataclass
class GateRaise:
    path: Path
    lineno: int
    message: str


@dataclass
class SourceGates:
    path: Path
    gates: list[GateRaise] = field(default_factory=list)
    # (lineno, reason) for in-scope raises whose message is not static text.
    unclassifiable: list[tuple[int, str]] = field(default_factory=list)
    # Raises that are not ValueError/RuntimeError (custom errors, KeyError,
    # SystemExit, bare re-raises) - out of scope for the bucket discipline.
    out_of_scope: int = 0


def _exception_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _static_text(node: ast.expr) -> str | None:
    """Best-effort static text of an expression; ``None`` when fully dynamic.

    JoinedStr (f-strings) keep every constant part, with ``<dyn>`` marking
    elided dynamic segments, so vocabulary after a placeholder (e.g.
    "... <dyn> exceeds <dyn> characters") still classifies. BinOp ``+``
    chains keep whichever side is static.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append(_DYNAMIC_PLACEHOLDER)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_text(node.left)
        right = _static_text(node.right)
        if left is not None and right is not None:
            return left + right
        if left is not None:
            return left + _DYNAMIC_PLACEHOLDER
        if right is not None:
            return _DYNAMIC_PLACEHOLDER + right
        return None
    return None


def extract_gate_raises(path: Path) -> SourceGates:
    """Parse ``path`` with ``ast`` and collect ValueError/RuntimeError gates."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    result = SourceGates(path=path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Raise):
            continue
        exc = node.exc
        if exc is None:  # bare ``raise`` (re-raise)
            result.out_of_scope += 1
            continue
        target = exc.func if isinstance(exc, ast.Call) else exc
        name = _exception_name(target)
        if name not in ("ValueError", "RuntimeError"):
            result.out_of_scope += 1
            continue
        if not isinstance(exc, ast.Call):
            result.unclassifiable.append((node.lineno, f"{name} raised without message"))
            continue
        if not exc.args:
            result.unclassifiable.append((node.lineno, f"{name}() without message"))
            continue
        first_arg = exc.args[0]
        if isinstance(first_arg, ast.Starred):
            result.unclassifiable.append((node.lineno, f"{name}(*args) - starred argument"))
            continue
        message = _static_text(first_arg)
        if message is None:
            result.unclassifiable.append((node.lineno, f"{name}(<dynamic message>)"))
            continue
        result.gates.append(GateRaise(path=path, lineno=node.lineno, message=message))
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_owner_gate_raises_are_bucketed() -> None:
    """Every ValueError/RuntimeError gate in the owner tools must fit a bucket."""
    unbucketed: list[str] = []
    unclassifiable_report: list[str] = []
    per_source: dict[str, dict[str, int]] = {}

    for source in OWNER_SOURCES:
        assert source.exists(), f"owner source missing: {source}"
        extracted = extract_gate_raises(source)
        minimum = MIN_GATES_PER_SOURCE[source.name]
        assert len(extracted.gates) >= minimum, (
            f"{source.name}: only {len(extracted.gates)} classifiable gates extracted "
            f"(expected at least {minimum}); did the extractor break or the owner "
            f"file move?"
        )

        counts = {bucket: 0 for bucket, _ in BUCKETS_IN_PRIORITY_ORDER}
        for gate in extracted.gates:
            bucket = classify_gate_message(gate.message)
            if bucket is None:
                unbucketed.append(
                    f"{gate.path.name}:{gate.lineno}: {gate.message!r}\n"
                    "    -> matches none of DANGER / REPORT / BOUNDED_FAILSAFE /\n"
                    "    FORMAT. Either this is a content-level gate (rework it: a\n"
                    "    mechanical gate must not judge WHAT to test), or extend the\n"
                    "    bucket registry in this file with a semantic pattern."
                )
            else:
                counts[bucket] += 1
        per_source[source.name] = counts

        for lineno, reason in extracted.unclassifiable:
            unclassifiable_report.append(
                f"{source.name}:{lineno}: {reason} - unclassifiable, manual review"
            )

    # Visible with `pytest -s` (and in failure output): per-source bucket
    # distribution plus the manual-review list for non-static messages.
    for name, counts in per_source.items():
        total = sum(counts.values())
        print(
            f"{name}: {total} gates "
            f"(danger={counts['DANGER']} report={counts['REPORT']} "
            f"bounded={counts['BOUNDED_FAILSAFE']} format={counts['FORMAT']})"
        )
    for line in unclassifiable_report:
        print(f"UNCLASSIFIABLE {line}")

    assert not unbucketed, (
        "Gate bucket discipline violated - mechanical gates outside every bucket:\n"
        + "\n".join(unbucketed)
    )


# Known content-level gate shapes: they judge WHICH vulnerability family or
# route may run, which is AI judgment, not a mechanical gate.
KNOWN_CONTENT_GATE_MESSAGES = [
    # The PRD's own injection example.
    "Action Queue refuses SQLi family without prior XSS coverage",
    "Skill route rejected: XSS requires completed recon lane before claim",
    "Queue refuses SSRF family without prior IDOR coverage",
]


def test_bucket_registry_rejects_content_gate() -> None:
    """Negative verification (implement.md 0.3) without touching tools/.

    A content-level gate must classify as unbucketed (``None``) so that
    ``test_owner_gate_raises_are_bucketed`` fails if such a gate is ever
    injected into an owner tool. This proves the defense itself works.
    """
    for message in KNOWN_CONTENT_GATE_MESSAGES:
        classified = classify_gate_message(message)
        assert classified is None, (
            f"content-level gate was classified as {classified!r} "
            f"(it must be unbucketed): {message!r}"
        )


def test_injected_content_gate_in_source_is_unbucketed(tmp_path: Path) -> None:
    """End-to-end negative verification on a temporary source file.

    Simulates the PRD scenario - a content-level gate injected into an owner
    tool - on a throwaway file (tools/ sources are never modified) and
    asserts the extract+classify pipeline leaves it unbucketed, which is
    exactly the failure condition of the main test.
    """
    source = tmp_path / "fake_owner.py"
    source.write_text(
        "def check() -> None:\n"
        "    raise ValueError(\n"
        "        'Action Queue refuses SQLi family without prior XSS coverage'\n"
        "    )\n",
        encoding="utf-8",
    )
    extracted = extract_gate_raises(source)
    assert len(extracted.gates) == 1
    assert extracted.unclassifiable == []
    assert classify_gate_message(extracted.gates[0].message) is None


REPRESENTATIVE_BUCKETED_MESSAGES = {
    "DANGER": "validation URL is outside target scope: https://evil.example",
    "REPORT": "Action Queue versioned resolve requires replayable last_outcome evidence",
    "BOUNDED_FAILSAFE": "Action Queue hypothesis action budget is exhausted",
    "FORMAT": "Action Queue active_dimension must be a single-dimension label",
}


def test_bucket_registry_classifies_representative_gates() -> None:
    """Control: representative gates still land in their expected buckets."""
    for bucket, message in REPRESENTATIVE_BUCKETED_MESSAGES.items():
        assert classify_gate_message(message) == bucket, (
            f"expected {bucket!r} for {message!r}"
        )


def test_bucket_patterns_compile() -> None:
    """Every registry pattern must be a valid regex (clear failure point)."""
    all_patterns: list[tuple[str, list[str]]] = [
        ("DANGER", DANGER_PATTERNS),
        ("REPORT", REPORT_PATTERNS),
        ("BOUNDED_FAILSAFE", BOUNDED_FAILSAFE_PATTERNS),
        ("FORMAT", FORMAT_PATTERNS),
        ("CONTENT_GATE", CONTENT_GATE_PATTERNS),
    ]
    for bucket, patterns in all_patterns:
        for pattern in patterns:
            re.compile(pattern)
