"""Lexical regression for commands/autopilot.md Mandatory Reflection Cadence.

Asserts that every Cadence trigger block + Question→Tool Reference row is
present in the installed `commands/autopilot.md`. Without this test, prompt
content can silently drift (line-wrap, heading rename, accidental delete)
and the cadence behavior measured against the lab apps no longer matches.

The cadence labs themselves live in `evidence/cadence-labs/*.py` — this
test keeps them anchored to the live prompt.
"""
from __future__ import annotations

import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
AUTOPILOT = REPO_ROOT / "commands" / "autopilot.md"


def _autopilot_text() -> str:
    assert AUTOPILOT.exists(), f"{AUTOPILOT} missing"
    return AUTOPILOT.read_text()


# ---------- Cadence trigger headings (5 blocks) ----------------------------

CADENCE_HEADINGS = [
    "### After every tool result",
    "### After a primary finding is validated",
    "### On 403 / 404 / 406 from an exposure candidate",
    "### On 3 consecutive identical-status responses on the same hypothesis",
    "### On auth-gated target (302 to /login, 401 from API)",
]


def test_cadence_headings_present():
    text = _autopilot_text()
    missing = [h for h in CADENCE_HEADINGS if h not in text]
    assert not missing, f"cadence headings missing: {missing}"


# ---------- Cadence trigger payload markers --------------------------------

CADENCE_PAYLOAD_MARKERS = [
    # [H][N][P] reflection line
    "[H] hypothesis alive?",
    "[N] next_question?",
    "[P] sibling/bypass/chain?",
    # 3-bypass triad per stack
    "trailing `;`",
    "off-by-slash",
    "`~1` shortname",
    "X-Forwarded-For",
    # [STALL] auto-rotate
    "[STALL]",
    "pick_next_lane",
    # auth-gated chain (prompt-only)
    "Prompt-only path first",
    "GET login → extract token → POST",
    # transport hint for raw-path payloads (Gap 1 fix)
    "Transport hint",
    "--path-as-is",
]


def test_cadence_payload_markers_present():
    text = _autopilot_text()
    missing = [m for m in CADENCE_PAYLOAD_MARKERS if m not in text]
    assert not missing, f"cadence payload markers missing: {missing}"


# ---------- Question → Tool Reference table rows ---------------------------

QUESTION_TOOL_REFERENCE_ROWS = [
    "`tools/role_diff.py`",
    "`run_js_read`",
    "`run_source_intel`",
    "`bypass-403`",
    "`tools/h1_oauth_tester.py`",
    "`tools/oast_listen.py`",
    "`tools/h1_race.py`",
    "`takeover`",
    "`tools/sibling_generator.py`",
    "`tools/coverage_matrix.py find-gaps`",
    "`tools/fresh_code.py`",
    "spawn `chain-builder` Task",
    "spawn `validator` Task",
    "spawn `report-writer` Task",
]


def test_question_tool_reference_rows_present():
    text = _autopilot_text()
    missing = [r for r in QUESTION_TOOL_REFERENCE_ROWS if r not in text]
    assert not missing, f"question→tool reference rows missing: {missing}"


# ---------- Step 0.5 + Step 0.6 anchors ------------------------------------

def test_target_fingerprint_and_stack_recall_present():
    text = _autopilot_text()
    assert "## Step 0.5: Target Fingerprint" in text
    assert "## Step 0.6: Stack Recall" in text
    # markdown line wraps split multi-word phrases across \n — normalize before searching
    flat = " ".join(text.split())
    # 0.6 must name at least one bug family per major stack so drift is caught
    for marker in (
        "OAuth", "SAML", "GraphQL", "IIS", "prototype pollution",
        "__NEXT_DATA__", "MFA",
    ):
        assert marker in flat, f"Step 0.6 missing stack marker: {marker}"


# ---------- Cadence labs ----------------------------------------------------

def test_cadence_labs_exist():
    base = REPO_ROOT / "evidence" / "cadence-labs"
    for stem in ("403_ladder.py", "stall_target.py", "auth_chain.py", "README.md"):
        assert (base / stem).exists(), f"cadence lab missing: {stem}"
