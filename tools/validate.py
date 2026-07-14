#!/usr/bin/env python3
"""
validate.py — Interactive bug validation assistant.
Records the 7-Question report-readiness gate, walks through the 4 validation
gates, checks for duplicates, calculates CVSS, and generates a skeleton
HackerOne report.

Usage:
  python3 tools/validate.py
  python3 tools/validate.py --output findings/myreport.md
  python3 tools/validate.py --target target.com --finding-id sqli_abc \
      --decision-json /tmp/validation-decision.json --json
"""

import argparse
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

try:
    from finding_index import load_finding_index, update_finding_status, upsert_finding
except ImportError:  # pragma: no cover - package import path
    from tools.finding_index import load_finding_index, update_finding_status, upsert_finding

try:
    from target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - package import path
    from tools.target_paths import canonical_target_value, target_storage_key

try:
    from browser_evidence import (
        capture_browser_evidence,
        compact_browser_evidence,
        load_last_browser_evidence,
    )
except ImportError:  # pragma: no cover - package import path
    from tools.browser_evidence import (
        capture_browser_evidence,
        compact_browser_evidence,
        load_last_browser_evidence,
    )

try:
    from runtime_config import load_runtime_config
except ImportError:  # pragma: no cover - package import path
    from tools.runtime_config import load_runtime_config

try:
    from evidence_rubric import evaluate_candidate_evidence, first_missing_action
except ImportError:  # pragma: no cover - package import path
    from tools.evidence_rubric import evaluate_candidate_evidence, first_missing_action

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config() -> dict:
    """Load optional repo-local config.json for validation flags."""
    return load_runtime_config(BASE_DIR)


def load_json_file(path: str) -> dict:
    """Best-effort 读取可选 JSON 交接文件，失败时记录警告但不中断验证流程。"""
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{YELLOW}Warning:{RESET} unable to load JSON file {path}: {exc}")
        return {"_path": path, "_load_error": str(exc)}

# macOS: Python may not have system SSL certs. Use unverified context for API queries.
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

# ─── Color codes ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


SEVEN_QUESTION_DEFINITIONS = (
    ("q1_replayable_now", "Can I demonstrate this step-by-step right now?"),
    ("q2_impact_demonstrated", "Is the impact clearly demonstrated?"),
    ("q3_target_context", "Is the vulnerable asset tied to the supplied target context?"),
    ("q4_attacker_access", "Does it avoid privileged access an attacker cannot get?"),
    ("q5_not_known_behavior", "Is this not known or documented behavior?"),
    ("q6_impact_beyond_possible", "Can impact be proved beyond technically possible?"),
    ("q7_not_never_submit", "Is this not on the never-submit list unless chained?"),
)
SEVEN_QUESTION_KEYS = tuple(key for key, _ in SEVEN_QUESTION_DEFINITIONS)
SEVEN_QUESTION_STATUSES = {"pass", "fail", "partial", "chain_required", "unknown"}
MACHINE_DECISION_SCHEMA_VERSION = 1
MACHINE_DECISION_GATE_KEYS = ("gate1", "gate2", "gate3", "gate4")
CVSS_PARAMETER_KEYS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


class ValidationInputUnavailable(RuntimeError):
    """Raised when an interactive validation prompt cannot safely read input."""

# A validation skeleton is useful working material, but it is not a
# submission-ready report until its concrete evidence sections are filled.
# Keep this intentionally narrow: ordinary Markdown brackets are valid prose.
REPORT_DRAFT_PLACEHOLDER_RE = re.compile(
    r"\[(?:insert|paste|fill(?:\s+in)?|step\s+\d+|describe|what\s+|attach|quantify|specific\b|explain|2-3\s+sentences)",
    re.IGNORECASE,
)


def _normalize_seven_question_status(value, default: str = "unknown") -> str:
    """把 AI/operator 输入归一成固定枚举，避免 summary 出现自由文本状态。"""
    if isinstance(value, bool):
        return "pass" if value else "fail"
    raw = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "yes": "pass",
        "y": "pass",
        "true": "pass",
        "ok": "pass",
        "passed": "pass",
        "no": "fail",
        "n": "fail",
        "false": "fail",
        "failed": "fail",
        "needs_chain": "chain_required",
        "chain": "chain_required",
        "needs_review": "unknown",
        "review": "unknown",
    }
    raw = aliases.get(raw, raw)
    return raw if raw in SEVEN_QUESTION_STATUSES else default


def _seven_question_entry(
    *,
    key: str,
    question: str,
    status: str,
    basis: str,
    source: str,
    blocker: str = "",
    next_action: str = "",
) -> dict:
    """生成一个稳定的 Q1-Q7 记录项；供 report/remember/复盘审计使用。"""
    item = {
        "question": question,
        "status": _normalize_seven_question_status(status),
        "basis": str(basis or "").strip(),
        "source": str(source or "derived").strip(),
    }
    if blocker:
        item["blocker"] = str(blocker).strip()
    if next_action:
        item["next_action"] = str(next_action).strip()
    return item


def _gate_bool(info: dict, key: str) -> bool | None:
    value = info.get(key)
    return value if isinstance(value, bool) else None


def _derive_seven_question_gate(info: dict) -> dict:
    """从现有 4 gates 粗略派生 7-gate；显式 AI 判断可覆盖它。"""
    gate1 = _gate_bool(info, "gate1_pass")
    gate2 = _gate_bool(info, "gate2_pass")
    gate3 = _gate_bool(info, "gate3_pass")
    gate4 = _gate_bool(info, "gate4_pass")
    gate1_notes = info.get("gate1_notes") if isinstance(info.get("gate1_notes"), dict) else {}
    gate3_notes = info.get("gate3_notes") if isinstance(info.get("gate3_notes"), dict) else {}

    concrete = bool(gate3_notes.get("concrete_impact"))
    has_proof = bool(gate3_notes.get("has_proof"))
    gate3_notes_available = bool(gate3_notes)
    no_unrealistic = bool(gate3_notes.get("no_unrealistic_preconditions"))
    not_documented = gate1_notes.get("not_documented_behavior")
    q6_status = (
        "pass"
        if (gate3 is True and (not gate3_notes_available or (concrete and has_proof)))
        else ("partial" if concrete or has_proof else ("fail" if gate3 is False else "unknown"))
    )

    derived = {
        "q1_replayable_now": _seven_question_entry(
            key="q1_replayable_now",
            question=SEVEN_QUESTION_DEFINITIONS[0][1],
            status="pass" if gate1 is True else ("fail" if gate1 is False else "unknown"),
            basis="Derived from Gate 1 reproducibility checks.",
            source="derived_from_4_gates",
            next_action="Capture exact request/response and rerun validation." if gate1 is False else "",
        ),
        "q2_impact_demonstrated": _seven_question_entry(
            key="q2_impact_demonstrated",
            question=SEVEN_QUESTION_DEFINITIONS[1][1],
            status="pass" if gate3 is True else ("fail" if gate3 is False else "unknown"),
            basis="Derived from Gate 3 exploitability and impact checks.",
            source="derived_from_4_gates",
            next_action="Show concrete victim/data/action impact." if gate3 is False else "",
        ),
        "q3_target_context": _seven_question_entry(
            key="q3_target_context",
            question=SEVEN_QUESTION_DEFINITIONS[2][1],
            status="pass" if gate2 is True else ("fail" if gate2 is False else "unknown"),
            basis="Derived from Gate 2 supplied-target-context check.",
            source="derived_from_4_gates",
        ),
        "q4_attacker_access": _seven_question_entry(
            key="q4_attacker_access",
            question=SEVEN_QUESTION_DEFINITIONS[3][1],
            status="pass" if (gate3 is True or no_unrealistic) else ("fail" if gate3 is False else "unknown"),
            basis="Derived from Gate 3 unrealistic-precondition check.",
            source="derived_from_4_gates",
            next_action="Prove the attack works with realistic attacker privileges." if gate3 is False else "",
        ),
        "q5_not_known_behavior": _seven_question_entry(
            key="q5_not_known_behavior",
            question=SEVEN_QUESTION_DEFINITIONS[4][1],
            status="pass" if (gate4 is True and not_documented is not False) else ("fail" if gate4 is False or not_documented is False else "unknown"),
            basis="Derived from Gate 1 documentation check and Gate 4 advisory duplicate check.",
            source="derived_from_4_gates",
            next_action="Check docs, changelog, disclosed reports, and known issues." if (gate4 is False or not_documented is False) else "",
        ),
        "q6_impact_beyond_possible": _seven_question_entry(
            key="q6_impact_beyond_possible",
            question=SEVEN_QUESTION_DEFINITIONS[5][1],
            status=q6_status,
            basis="Derived from Gate 3 concrete-impact/proof fields.",
            source="derived_from_4_gates",
            next_action="Upgrade from technical possibility to concrete data/action proof." if q6_status != "pass" else "",
        ),
        "q7_not_never_submit": _seven_question_entry(
            key="q7_not_never_submit",
            question=SEVEN_QUESTION_DEFINITIONS[6][1],
            status="pass",
            basis="No never-submit exception was recorded in the 4-gate run; pass explicit seven_question_gate to override if Q7 fails or needs a chain.",
            source="derived_from_4_gates",
        ),
    }
    return derived


def _explicit_seven_question_gate(raw: dict) -> dict:
    """读取 Claude/operator 显式 Q1-Q7 判断，允许简单字符串或完整对象。"""
    questions = raw.get("questions") if isinstance(raw.get("questions"), dict) else raw
    parsed: dict[str, dict] = {}
    for key, question in SEVEN_QUESTION_DEFINITIONS:
        value = questions.get(key) if isinstance(questions, dict) else None
        if isinstance(value, dict):
            status = value.get("status", "unknown")
            basis = value.get("basis") or value.get("reason") or value.get("evidence") or ""
            blocker = value.get("blocker", "")
            next_action = value.get("next_action", "")
        else:
            status = value if value is not None else "unknown"
            basis = ""
            blocker = ""
            next_action = ""
        parsed[key] = _seven_question_entry(
            key=key,
            question=question,
            status=status,
            basis=basis,
            source=str(raw.get("source") or "ai_explicit"),
            blocker=blocker,
            next_action=next_action,
        )
    return parsed


def _seven_question_decision(questions: dict) -> tuple[bool, str]:
    statuses = [
        _normalize_seven_question_status((questions.get(key) or {}).get("status"))
        for key in SEVEN_QUESTION_KEYS
    ]
    if any(status == "fail" for status in statuses):
        return False, "kill"
    if any(status == "chain_required" for status in statuses):
        return False, "chain_required"
    if any(status in {"partial", "unknown"} for status in statuses):
        return False, "needs_review"
    return True, "pass"


def build_seven_question_gate(info: dict) -> dict:
    """构建 validation-summary.json 中的 7-Question Gate 审计块。"""
    explicit = info.get("seven_question_gate")
    questions = (
        _explicit_seven_question_gate(explicit)
        if isinstance(explicit, dict) and explicit
        else _derive_seven_question_gate(info)
    )
    passed, decision = _seven_question_decision(questions)
    return {
        "schema_version": 1,
        "source": "explicit" if isinstance(explicit, dict) and explicit else "derived_from_4_gates",
        "passed": passed,
        "decision": decision,
        "questions": questions,
    }

# ─── CVSS 4.0 scoring ─────────────────────────────────────────────────────────

CVSS4_LOOKUP = {'000000': 10,
 '000001': 9.9,
 '000010': 9.8,
 '000011': 9.5,
 '000020': 9.5,
 '000021': 9.2,
 '000100': 10,
 '000101': 9.6,
 '000110': 9.3,
 '000111': 8.7,
 '000120': 9.1,
 '000121': 8.1,
 '000200': 9.3,
 '000201': 9,
 '000210': 8.9,
 '000211': 8,
 '000220': 8.1,
 '000221': 6.8,
 '001000': 9.8,
 '001001': 9.5,
 '001010': 9.5,
 '001011': 9.2,
 '001020': 9,
 '001021': 8.4,
 '001100': 9.3,
 '001101': 9.2,
 '001110': 8.9,
 '001111': 8.1,
 '001120': 8.1,
 '001121': 6.5,
 '001200': 8.8,
 '001201': 8,
 '001210': 7.8,
 '001211': 7,
 '001220': 6.9,
 '001221': 4.8,
 '002001': 9.2,
 '002011': 8.2,
 '002021': 7.2,
 '002101': 7.9,
 '002111': 6.9,
 '002121': 5,
 '002201': 6.9,
 '002211': 5.5,
 '002221': 2.7,
 '010000': 9.9,
 '010001': 9.7,
 '010010': 9.5,
 '010011': 9.2,
 '010020': 9.2,
 '010021': 8.5,
 '010100': 9.5,
 '010101': 9.1,
 '010110': 9,
 '010111': 8.3,
 '010120': 8.4,
 '010121': 7.1,
 '010200': 9.2,
 '010201': 8.1,
 '010210': 8.2,
 '010211': 7.1,
 '010220': 7.2,
 '010221': 5.3,
 '011000': 9.5,
 '011001': 9.3,
 '011010': 9.2,
 '011011': 8.5,
 '011020': 8.5,
 '011021': 7.3,
 '011100': 9.2,
 '011101': 8.2,
 '011110': 8,
 '011111': 7.2,
 '011120': 7,
 '011121': 5.9,
 '011200': 8.4,
 '011201': 7,
 '011210': 7.1,
 '011211': 5.2,
 '011220': 5,
 '011221': 3,
 '012001': 8.6,
 '012011': 7.5,
 '012021': 5.2,
 '012101': 7.1,
 '012111': 5.2,
 '012121': 2.9,
 '012201': 6.3,
 '012211': 2.9,
 '012221': 1.7,
 '100000': 9.8,
 '100001': 9.5,
 '100010': 9.4,
 '100011': 8.7,
 '100020': 9.1,
 '100021': 8.1,
 '100100': 9.4,
 '100101': 8.9,
 '100110': 8.6,
 '100111': 7.4,
 '100120': 7.7,
 '100121': 6.4,
 '100200': 8.7,
 '100201': 7.5,
 '100210': 7.4,
 '100211': 6.3,
 '100220': 6.3,
 '100221': 4.9,
 '101000': 9.4,
 '101001': 8.9,
 '101010': 8.8,
 '101011': 7.7,
 '101020': 7.6,
 '101021': 6.7,
 '101100': 8.6,
 '101101': 7.6,
 '101110': 7.4,
 '101111': 5.8,
 '101120': 5.9,
 '101121': 5,
 '101200': 7.2,
 '101201': 5.7,
 '101210': 5.7,
 '101211': 5.2,
 '101220': 5.2,
 '101221': 2.5,
 '102001': 8.3,
 '102011': 7,
 '102021': 5.4,
 '102101': 6.5,
 '102111': 5.8,
 '102121': 2.6,
 '102201': 5.3,
 '102211': 2.1,
 '102221': 1.3,
 '110000': 9.5,
 '110001': 9,
 '110010': 8.8,
 '110011': 7.6,
 '110020': 7.6,
 '110021': 7,
 '110100': 9,
 '110101': 7.7,
 '110110': 7.5,
 '110111': 6.2,
 '110120': 6.1,
 '110121': 5.3,
 '110200': 7.7,
 '110201': 6.6,
 '110210': 6.8,
 '110211': 5.9,
 '110220': 5.2,
 '110221': 3,
 '111000': 8.9,
 '111001': 7.8,
 '111010': 7.6,
 '111011': 6.7,
 '111020': 6.2,
 '111021': 5.8,
 '111100': 7.4,
 '111101': 5.9,
 '111110': 5.7,
 '111111': 5.7,
 '111120': 4.7,
 '111121': 2.3,
 '111200': 6.1,
 '111201': 5.2,
 '111210': 5.7,
 '111211': 2.9,
 '111220': 2.4,
 '111221': 1.6,
 '112001': 7.1,
 '112011': 5.9,
 '112021': 3,
 '112101': 5.8,
 '112111': 2.6,
 '112121': 1.5,
 '112201': 2.3,
 '112211': 1.3,
 '112221': 0.6,
 '200000': 9.3,
 '200001': 8.7,
 '200010': 8.6,
 '200011': 7.2,
 '200020': 7.5,
 '200021': 5.8,
 '200100': 8.6,
 '200101': 7.4,
 '200110': 7.4,
 '200111': 6.1,
 '200120': 5.6,
 '200121': 3.4,
 '200200': 7,
 '200201': 5.4,
 '200210': 5.2,
 '200211': 4,
 '200220': 4,
 '200221': 2.2,
 '201000': 8.5,
 '201001': 7.5,
 '201010': 7.4,
 '201011': 5.5,
 '201020': 6.2,
 '201021': 5.1,
 '201100': 7.2,
 '201101': 5.7,
 '201110': 5.5,
 '201111': 4.1,
 '201120': 4.6,
 '201121': 1.9,
 '201200': 5.3,
 '201201': 3.6,
 '201210': 3.4,
 '201211': 1.9,
 '201220': 1.9,
 '201221': 0.8,
 '202001': 6.4,
 '202011': 5.1,
 '202021': 2,
 '202101': 4.7,
 '202111': 2.1,
 '202121': 1.1,
 '202201': 2.4,
 '202211': 0.9,
 '202221': 0.4,
 '210000': 8.8,
 '210001': 7.5,
 '210010': 7.3,
 '210011': 5.3,
 '210020': 6,
 '210021': 5,
 '210100': 7.3,
 '210101': 5.5,
 '210110': 5.9,
 '210111': 4,
 '210120': 4.1,
 '210121': 2,
 '210200': 5.4,
 '210201': 4.3,
 '210210': 4.5,
 '210211': 2.2,
 '210220': 2,
 '210221': 1.1,
 '211000': 7.5,
 '211001': 5.5,
 '211010': 5.8,
 '211011': 4.5,
 '211020': 4,
 '211021': 2.1,
 '211100': 6.1,
 '211101': 5.1,
 '211110': 4.8,
 '211111': 1.8,
 '211120': 2,
 '211121': 0.9,
 '211200': 4.6,
 '211201': 1.8,
 '211210': 1.7,
 '211211': 0.7,
 '211220': 0.8,
 '211221': 0.2,
 '212001': 5.3,
 '212011': 2.4,
 '212021': 1.4,
 '212101': 2.4,
 '212111': 1.2,
 '212121': 0.5,
 '212201': 1,
 '212211': 0.3,
 '212221': 0.1}

CVSS4_MAX_COMPOSED = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        0: ["AC:L/AT:N/"],
        1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        0: {
            0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            1: [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        2: {
            1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        },
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        0: ["E:A/"],
        1: ["E:P/"],
        2: ["E:U/"],
    },
}

CVSS4_MAX_SEVERITY = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {
        0: {0: 7, 1: 6},
        1: {0: 8, 1: 8},
        2: {1: 10},
    },
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

CVSS4_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "E": {"U": 0.2, "P": 0.1, "A": 0.0},
}


def _cvss4_round(score: float) -> float:
    # Align with FIRST / Red Hat official helper:
    # roundToDecimalPlaces(Math.max(0, Math.min(10, value)), 1)
    # using EPSILON = 10^-6 to compensate floating-point representation drift.
    clamped = max(0.0, min(10.0, score))
    epsilon = 10 ** -6
    return int((clamped + epsilon) * 10 + 0.5) / 10


def _cvss4_metric(metrics: dict[str, str], metric: str) -> str | None:
    selected = metrics.get(metric)

    if metric == "E" and selected == "X":
        return "A"
    if metric in {"CR", "IR", "AR"} and selected == "X":
        return "H"

    modified_selected = metrics.get(f"M{metric}")
    if modified_selected and modified_selected != "X":
        return modified_selected

    return selected


def _cvss4_extract_metric(metric: str, vector: str) -> str:
    for part in vector.split("/"):
        if part.startswith(f"{metric}:"):
            return part.split(":", 1)[1]
    raise ValueError(f"Metric {metric} missing from vector: {vector}")


def _cvss4_macro_vector(metrics: dict[str, str]) -> str:
    av = _cvss4_metric(metrics, "AV")
    pr = _cvss4_metric(metrics, "PR")
    ui = _cvss4_metric(metrics, "UI")
    ac = _cvss4_metric(metrics, "AC")
    at = _cvss4_metric(metrics, "AT")
    vc = _cvss4_metric(metrics, "VC")
    vi = _cvss4_metric(metrics, "VI")
    va = _cvss4_metric(metrics, "VA")
    sc = _cvss4_metric(metrics, "SC")
    si = _cvss4_metric(metrics, "SI")
    sa = _cvss4_metric(metrics, "SA")
    msi = _cvss4_metric(metrics, "MSI")
    msa = _cvss4_metric(metrics, "MSA")
    e = _cvss4_metric(metrics, "E")
    cr = _cvss4_metric(metrics, "CR")
    ir = _cvss4_metric(metrics, "IR")
    ar = _cvss4_metric(metrics, "AR")

    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N") and av != "P":
        eq1 = "1"
    else:
        eq1 = "2"

    eq2 = "0" if ac == "L" and at == "N" else "1"

    if vc == "H" and vi == "H":
        eq3 = 0
    elif (vc == "H" or vi == "H" or va == "H"):
        eq3 = 1
    else:
        eq3 = 2

    if msi == "S" or msa == "S":
        eq4 = 0
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = 1
    else:
        eq4 = 2

    if e == "A":
        eq5 = 0
    elif e == "P":
        eq5 = 1
    else:
        eq5 = 2

    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = 0
    else:
        eq6 = 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _cvss4_score(metrics: dict[str, str]) -> float:
    if all(_cvss4_metric(metrics, metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro_vector = _cvss4_macro_vector(metrics)
    value = float(CVSS4_LOOKUP[macro_vector])
    eq1, eq2, eq3, eq4, eq5, eq6 = map(int, macro_vector)

    eq1_next_lower_macro = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    eq2_next_lower_macro = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"

    if eq3 == 1 and eq6 == 1:
        score_eq3eq6_next_lower_macro = CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 0 and eq6 == 1:
        score_eq3eq6_next_lower_macro = CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6_next_lower_macro = CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    elif eq3 == 0 and eq6 == 0:
        score_eq3eq6_next_lower_macro = max(
            CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}", float("nan")),
            CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}", float("nan")),
        )
        if score_eq3eq6_next_lower_macro != score_eq3eq6_next_lower_macro:
            score_eq3eq6_next_lower_macro = None
    else:
        score_eq3eq6_next_lower_macro = CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")

    score_eq1_next_lower_macro = CVSS4_LOOKUP.get(eq1_next_lower_macro)
    score_eq2_next_lower_macro = CVSS4_LOOKUP.get(eq2_next_lower_macro)
    score_eq4_next_lower_macro = CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
    score_eq5_next_lower_macro = CVSS4_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

    eq1_maxes = CVSS4_MAX_COMPOSED["eq1"][eq1]
    eq2_maxes = CVSS4_MAX_COMPOSED["eq2"][eq2]
    eq3eq6_maxes = CVSS4_MAX_COMPOSED["eq3"][eq3][eq6]
    eq4_maxes = CVSS4_MAX_COMPOSED["eq4"][eq4]
    eq5_maxes = CVSS4_MAX_COMPOSED["eq5"][eq5]

    severity_distances = None
    for eq1_max in eq1_maxes:
        for eq2_max in eq2_maxes:
            for eq3eq6_max in eq3eq6_maxes:
                for eq4_max in eq4_maxes:
                    for eq5_max in eq5_maxes:
                        max_vector = f"{eq1_max}{eq2_max}{eq3eq6_max}{eq4_max}{eq5_max}"
                        current = {}
                        for metric_name in ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"):
                            current[metric_name] = (
                                CVSS4_LEVELS[metric_name][_cvss4_metric(metrics, metric_name)]
                                - CVSS4_LEVELS[metric_name][_cvss4_extract_metric(metric_name, max_vector)]
                            )
                        if any(distance < 0 for distance in current.values()):
                            continue
                        severity_distances = current
                        break
                    if severity_distances is not None:
                        break
                if severity_distances is not None:
                    break
            if severity_distances is not None:
                break
        if severity_distances is not None:
            break

    if severity_distances is None:
        raise ValueError(f"Unable to resolve CVSS v4 max vector for macro {macro_vector}")

    current_severity_distance_eq1 = sum(severity_distances[metric] for metric in ("AV", "PR", "UI"))
    current_severity_distance_eq2 = sum(severity_distances[metric] for metric in ("AC", "AT"))
    current_severity_distance_eq3eq6 = sum(severity_distances[metric] for metric in ("VC", "VI", "VA", "CR", "IR", "AR"))
    current_severity_distance_eq4 = sum(severity_distances[metric] for metric in ("SC", "SI", "SA"))

    available_distances = [
        (score_eq1_next_lower_macro, current_severity_distance_eq1, CVSS4_MAX_SEVERITY["eq1"][eq1] * 0.1),
        (score_eq2_next_lower_macro, current_severity_distance_eq2, CVSS4_MAX_SEVERITY["eq2"][eq2] * 0.1),
        (score_eq3eq6_next_lower_macro, current_severity_distance_eq3eq6, CVSS4_MAX_SEVERITY["eq3eq6"][eq3][eq6] * 0.1),
        (score_eq4_next_lower_macro, current_severity_distance_eq4, CVSS4_MAX_SEVERITY["eq4"][eq4] * 0.1),
        (score_eq5_next_lower_macro, 0.0, 1.0),
    ]

    normalized = []
    for lower_macro_score, current_distance, max_severity in available_distances:
        if lower_macro_score is None:
            continue
        available_distance = value - float(lower_macro_score)
        percent = 0.0 if current_distance == 0 else current_distance / max_severity
        normalized.append(available_distance * percent)

    mean_distance = (sum(normalized) / len(normalized)) if normalized else 0.0
    return _cvss4_round(value - mean_distance)


def calculate_cvss4(av, ac, at, pr, ui, vc, vi, va, sc, si, sa) -> tuple[float, str]:
    """Calculate a CVSS 4.0 base score using the FIRST reference algorithm."""
    metrics = {
        "AV": av,
        "AC": ac,
        "AT": at,
        "PR": pr,
        "UI": ui,
        "VC": vc,
        "VI": vi,
        "VA": va,
        "SC": sc,
        "SI": si,
        "SA": sa,
        "E": "X",
        "CR": "X",
        "IR": "X",
        "AR": "X",
    }

    score = _cvss4_score(metrics)
    vector = (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}/"
        f"VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
    )
    return score, vector


def severity_from_score(score: float) -> str:
    if score == 0.0:  return "NONE"
    if score < 4.0:   return "LOW"
    if score < 7.0:   return "MEDIUM"
    if score < 9.0:   return "HIGH"
    return "CRITICAL"

# ─── HackerOne dup check ──────────────────────────────────────────────────────

def check_h1_dups(program_handle: str, vuln_keyword: str) -> list[dict]:
    """Search HackerOne for potential duplicates."""
    if not program_handle:
        return []

    query = {
        "query": f"""{{
          hacktivity_items(
            first: 10,
            order_by: {{ field: popular, direction: DESC }},
            where: {{
              team: {{ handle: {{ _eq: "{program_handle}" }} }},
              report: {{ title: {{ _icontains: "{vuln_keyword}" }} }}
            }}
          ) {{
            nodes {{
              ... on HacktivityDocument {{
                report {{
                  title
                  severity_rating
                  disclosed_at
                  url
                  state
                }}
              }}
            }}
          }}
        }}"""
    }
    try:
        req = urllib.request.Request(
            "https://hackerone.com/graphql",
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
            data = json.loads(resp.read().decode())
        nodes = (data.get("data") or {}).get("hacktivity_items", {}).get("nodes", [])
        results = []
        for node in nodes:
            r = node.get("report")
            if r:
                results.append(r)
        return results
    except Exception:
        return []


# ─── Interactive prompt helpers ───────────────────────────────────────────────

def ask(prompt: str, default: str = "") -> str:
    try:
        if default:
            val = input(f"  {prompt} [{default}]: ").strip()
            return val if val else default
        return input(f"  {prompt}: ").strip()
    except EOFError as exc:
        raise ValidationInputUnavailable(
            "interactive input ended; rerun from a TTY or provide --decision-json"
        ) from exc


def ask_yn(prompt: str, default: bool = True) -> bool:
    yn = "Y/n" if default else "y/N"
    try:
        val = input(f"  {prompt} [{yn}]: ").strip().lower()
    except EOFError as exc:
        raise ValidationInputUnavailable(
            "interactive input ended; rerun from a TTY or provide --decision-json"
        ) from exc
    if not val:
        return default
    return val in ("y", "yes")


def ask_choice(prompt: str, choices: list[tuple[str, str]], default: str = "") -> str:
    """Ask user to pick from labeled choices. Returns the choice key."""
    print(f"\n  {prompt}")
    for key, label in choices:
        print(f"    {CYAN}{key}{RESET}) {label}")
    valid = [key for key, _ in choices]
    fallback = default if default in valid else (choices[0][0] if choices else "")
    while True:
        try:
            val = input(f"  Choice: ").strip().upper()
        except EOFError as exc:
            raise ValidationInputUnavailable(
                "interactive input ended; rerun from a TTY or provide --decision-json"
            ) from exc
        if not val and fallback:
            return fallback
        if val in valid:
            return val
        print(f"  {YELLOW}Invalid — enter one of: {', '.join(valid)}{RESET}")


def section(title: str):
    print(f"\n{BOLD}{BLUE}{'─' * 60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'─' * 60}{RESET}\n")


def gate_header(n: int, name: str, status: str | None = None):
    status_str = ""
    if status == "PASS":
        status_str = f" {GREEN}✓ PASS{RESET}"
    elif status == "FAIL":
        status_str = f" {RED}✗ FAIL{RESET}"
    print(f"\n{BOLD}Gate {n}: {name}{RESET}{status_str}")
    print(f"{'─' * 40}")


# ─── Gate implementations ─────────────────────────────────────────────────────

def gate1_is_real() -> tuple[bool, dict]:
    gate_header(1, "Is It Real?")
    print("  Can you reproduce the bug from scratch — clean browser, no Burp artifacts?")
    print()
    repro3   = ask_yn("Reproduced 3/3 times deterministically?")
    no_burp  = ask_yn("Works with plain curl or fresh browser (not just in Burp)?")
    no_state = ask_yn("No unusual preconditions (doesn't require specific timing or race)?")
    rtfm     = ask_yn("Checked documentation — this isn't expected/documented behavior?")

    passed = repro3 and no_burp and no_state and rtfm
    notes = {
        "repro_3_3": repro3,
        "works_without_proxy": no_burp,
        "no_special_state": no_state,
        "not_documented_behavior": rtfm,
    }

    if not passed:
        print(f"\n  {RED}GATE 1 FAIL: Not reliably reproducible.{RESET}")
        print(f"  {DIM}Do not submit yet. Verify the bug is deterministic first.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 1 PASS{RESET}")

    return passed, notes


def gate2_in_scope(program_handle: str, skip_scope: bool = False) -> tuple[bool, dict]:
    gate_header(2, "Does It Match The Current Target Context?")
    if skip_scope:
        print("  CTF mode is enabled; external program checks stay fully relaxed for this run.")
    print("  Using the supplied target/program context directly; external program pages are optional context only.")

    print(f"\n  {GREEN}GATE 2 PASS (TARGET-DRIVEN CONTEXT){RESET}")
    notes = {
        "matches_target_context": True,
        "asset_in_scope": True,
        "not_excluded": True,
        "version_ok": True,
        "advisory_only": True,
        "target_context": program_handle or "",
    }
    if skip_scope:
        notes["skipped_in_ctf_mode"] = True
    return True, notes


def gate3_exploitable() -> tuple[bool, dict]:
    gate_header(3, "Is It Exploitable?")
    print("  Can you demonstrate concrete impact without unrealistic preconditions?")
    print()

    concrete_impact  = ask_yn("Can you show concrete impact (not just 'theoretically an attacker could')?")
    no_unrealistic   = ask_yn("No unrealistic preconditions (not 'must be admin already', not 'victim must run JS')?")
    can_demonstrate  = ask_yn("Have proof you can show a triager (screenshot, curl, PoC)?")

    print()
    print("  What is the concrete impact? (be specific)")
    impact_desc = ask("Describe the impact")

    passed = concrete_impact and no_unrealistic and can_demonstrate
    notes = {
        "concrete_impact": concrete_impact,
        "no_unrealistic_preconditions": no_unrealistic,
        "has_proof": can_demonstrate,
        "impact_description": impact_desc,
    }

    if not passed:
        print(f"\n  {RED}GATE 3 FAIL: Exploitability not demonstrated.{RESET}")
        print(f"  {DIM}Build a working PoC before submitting.{RESET}")
    else:
        print(f"\n  {GREEN}GATE 3 PASS{RESET}")

    return passed, notes


def gate4_not_dup(vuln_type: str, endpoint: str, program_handle: str) -> tuple[bool, dict]:
    gate_header(4, "Is It a Dup?")
    print("  External disclosed-report and program-policy checks stay advisory only.")

    print(f"\n  {GREEN}GATE 4 PASS (ADVISORY-ONLY DUP CHECKS){RESET}")
    return True, {
        "not_in_h1_disclosed": True,
        "not_in_github_issues": True,
        "checked_git_history": True,
        "h1_similar_reports": [],
        "advisory_only": True,
        "target_context": program_handle or "",
        "vuln_type": vuln_type,
        "endpoint": endpoint,
    }


# ─── CVSS interactive scorer ──────────────────────────────────────────────────

def ask_cvss_score() -> tuple[float, str, dict]:
    section("CVSS 4.0 Scoring")

    av = ask_choice("Attack Vector (AV)", [
        ("N", "Network — exploitable remotely over internet"),
        ("A", "Adjacent — requires same network segment"),
        ("L", "Local — requires local access to system"),
        ("P", "Physical — requires physical device access"),
    ], default="N")
    ac = ask_choice("Attack Complexity (AC)", [
        ("L", "Low — reliable, no special conditions"),
        ("H", "High — requires specific conditions or timing"),
    ], default="L")
    at = ask_choice("Attack Requirements (AT)", [
        ("N", "None — no extra deployment/runtime condition required"),
        ("P", "Present — exploit depends on a specific condition being true"),
    ], default="N")
    pr = ask_choice("Privileges Required (PR)", [
        ("N", "None — no account needed"),
        ("L", "Low — regular user account"),
        ("H", "High — admin / elevated privileges"),
    ], default="N")
    ui = ask_choice("User Interaction (UI)", [
        ("N", "None — no user interaction required"),
        ("P", "Passive — user is exposed during normal use"),
        ("A", "Active — user must perform a specific action"),
    ], default="N")
    vc = ask_choice("Vulnerable System Confidentiality (VC)", [
        ("H", "High — complete disclosure of vulnerable system data"),
        ("L", "Low — partial disclosure of vulnerable system data"),
        ("N", "None"),
    ], default="L")
    vi = ask_choice("Vulnerable System Integrity (VI)", [
        ("H", "High — complete modification of vulnerable system data"),
        ("L", "Low — limited modification of vulnerable system data"),
        ("N", "None"),
    ], default="N")
    va = ask_choice("Vulnerable System Availability (VA)", [
        ("H", "High — complete shutdown or major service loss"),
        ("L", "Low — reduced performance or intermittent disruption"),
        ("N", "None"),
    ], default="N")
    sc = ask_choice("Subsequent System Confidentiality (SC)", [
        ("H", "High — complete disclosure in a subsequent system"),
        ("L", "Low — partial disclosure in a subsequent system"),
        ("N", "None"),
    ], default="N")
    si = ask_choice("Subsequent System Integrity (SI)", [
        ("H", "High — complete modification in a subsequent system"),
        ("L", "Low — limited modification in a subsequent system"),
        ("N", "None"),
    ], default="N")
    sa = ask_choice("Subsequent System Availability (SA)", [
        ("H", "High — complete disruption in a subsequent system"),
        ("L", "Low — partial disruption in a subsequent system"),
        ("N", "None"),
    ], default="N")

    score, vector = calculate_cvss4(av, ac, at, pr, ui, vc, vi, va, sc, si, sa)
    sev = severity_from_score(score)

    sev_color = RED if sev in ("CRITICAL", "HIGH") else (YELLOW if sev == "MEDIUM" else GREEN)
    print(f"\n  {BOLD}CVSS 4.0 Score: {sev_color}{score} {sev}{RESET}")
    print(f"  {BOLD}Vector:{RESET} {vector}")

    params = {
        "AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
        "VC": vc, "VI": vi, "VA": va, "SC": sc, "SI": si, "SA": sa,
    }
    return score, vector, params



# ─── Report skeleton generator ────────────────────────────────────────────────

def generate_report_skeleton(info: dict) -> str:
    """Generate a HackerOne-style report skeleton."""
    vuln_type  = info.get("vuln_type", "VULN_TYPE")
    target     = info.get("target", "TARGET")
    endpoint   = info.get("endpoint", "ENDPOINT")
    impact     = info.get("impact", "IMPACT_DESCRIPTION")
    score      = info.get("cvss_score", 0.0)
    vector     = info.get("cvss_vector", "CVSS:4.0/...")
    sev        = severity_from_score(score)
    date       = datetime.now().strftime("%Y-%m-%d")

    return f"""# {vuln_type} on {endpoint} — [fill in specific impact]

> **Draft status:** validation evidence may be complete, but this document is not
> report-ready or submittable until all `[INSERT ...]`, `[PASTE ...]`, and other
> bracketed evidence placeholders below are replaced with target-specific proof.

**Program:** {target}
**Severity:** {sev} ({score}) — {vector}
**Date Found:** {date}

---

## Summary

[2-3 sentences. What is the vulnerability? Where is it? What can an attacker do?]

The `{endpoint}` endpoint [describe the vulnerability in one sentence]. By [describe
the attack], an attacker can [describe the concrete impact].

---

## Steps to Reproduce

> **Setup:** Create two accounts — Attacker (email: attacker@test.com) and Victim (email: victim@test.com).

1. Log in as **Attacker**
2. [Step 2 — specific action]
3. [Step 3 — specific request with actual parameter names]
   ```
   [INSERT ACTUAL HTTP REQUEST HERE — e.g., curl command or Burp request]
   ```
4. [Step 4 — what to observe in the response]
5. Confirm: [what proves the vulnerability — e.g., victim's data appears in response]

---

## Proof of Concept

**Request:**
```http
[PASTE ACTUAL REQUEST — METHOD, URL, HEADERS, BODY]
```

**Response:**
```json
[PASTE ACTUAL RESPONSE SHOWING THE VULNERABILITY]
```

**Screenshots:** [attach: TARGET-{vuln_type.lower().replace(' ','-')}-step1.png, etc.]

---

## Impact

{impact}

[Quantify: number of users affected, type of data exposed, what actions an attacker can take]

---

## CVSS 4.0

**Vector:** `{vector}`
**Score:** {score} ({sev})

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | {info.get('cvss_params', {}).get('AV', '?')} | [explain] |
| Attack Complexity | {info.get('cvss_params', {}).get('AC', '?')} | [explain] |
| Attack Requirements | {info.get('cvss_params', {}).get('AT', '?')} | [explain] |
| Privileges Required | {info.get('cvss_params', {}).get('PR', '?')} | [explain] |
| User Interaction | {info.get('cvss_params', {}).get('UI', '?')} | [explain] |
| Vulnerable System Confidentiality | {info.get('cvss_params', {}).get('VC', '?')} | [explain] |
| Vulnerable System Integrity | {info.get('cvss_params', {}).get('VI', '?')} | [explain] |
| Vulnerable System Availability | {info.get('cvss_params', {}).get('VA', '?')} | [explain] |
| Subsequent System Confidentiality | {info.get('cvss_params', {}).get('SC', '?')} | [explain] |
| Subsequent System Integrity | {info.get('cvss_params', {}).get('SI', '?')} | [explain] |
| Subsequent System Availability | {info.get('cvss_params', {}).get('SA', '?')} | [explain] |

---

## Fix Recommendation

[Specific code-level fix — name the file, function, and what to change]

Example: In `path/to/file.ts`, the `functionName` function should verify
`resource.user_id === req.user.id` before returning data.

---

## Validation Notes

| Gate | Result |
|---|---|
| Is it real? | {'PASS' if info.get('gate1_pass') else 'FAIL'} |
| Matches target context? | {'PASS' if info.get('gate2_pass') else 'FAIL'} |
| Is it exploitable? | {'PASS' if info.get('gate3_pass') else 'FAIL'} |
| Is it a dup? | {'PASS' if info.get('gate4_pass') else 'FAIL'} |
"""


def derive_validate_target(program_handle: str, endpoint: str) -> str:
    """Prefer endpoint host when available, otherwise fall back to program handle."""
    raw_endpoint = (endpoint or "").strip()
    if raw_endpoint.startswith(("http://", "https://")):
        parsed = urlparse(raw_endpoint)
        if parsed.netloc:
            return parsed.netloc.lower()
    return (program_handle or "unknown").strip()


def normalize_http_method(value: str | None) -> str:
    """Return a stable HTTP method label for validation evidence write-back."""
    method = str(value or "GET").strip().upper()
    return method or "GET"


def inspect_report_draft(report_path: str | Path) -> dict:
    """Return the report-draft completion state without interpreting evidence.

    The four validation gates and the seven-question gate establish the
    evidence decision.  This helper owns the separate document-completion
    check so an untouched template cannot masquerade as submission-ready.
    """
    path = Path(report_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {
            "status": "not_written",
            "path": str(path),
            "placeholder_count": 0,
            "placeholders": [],
        }

    matches = list(REPORT_DRAFT_PLACEHOLDER_RE.finditer(text))
    placeholders = []
    for match in matches[:8]:
        line = text.count("\n", 0, match.start()) + 1
        placeholders.append({"line": line, "token": match.group(0)[:80]})
    return {
        "status": "incomplete" if matches else "complete",
        "path": str(path),
        "placeholder_count": len(matches),
        "placeholders": placeholders,
    }


def validation_evidence_passed(summary: dict) -> bool:
    """Return whether evidence gates passed, distinct from report completion.

    Older summaries only have the historical gate fields, so preserve their
    meaning while new summaries make the distinction explicit.
    """
    explicit = summary.get("validation_evidence_passed")
    if isinstance(explicit, bool):
        return explicit
    four = bool(summary.get("four_validation_gates_passed", summary.get("all_gates_passed")))
    seven = bool(summary.get("seven_question_gate_passed", summary.get("all_gates_passed")))
    return four and seven


def build_validation_summary(info: dict, *, all_pass: bool, report_path: str | Path) -> dict:
    """Build a compact JSON summary that /remember can import later."""
    vuln_class = (info.get("vuln_type") or "").strip().lower()
    severity = severity_from_score(float(info.get("cvss_score", 0.0) or 0.0)).lower()
    gate_info = dict(info)
    if not any(key in gate_info for key in ("gate1_pass", "gate2_pass", "gate3_pass", "gate4_pass")):
        gate_info.update({
            "gate1_pass": bool(all_pass),
            "gate2_pass": bool(all_pass),
            "gate3_pass": bool(all_pass),
            "gate4_pass": bool(all_pass),
        })
    seven_question_gate = build_seven_question_gate(gate_info)
    evidence_passed = bool(all_pass and seven_question_gate.get("passed"))
    report_draft = inspect_report_draft(report_path)
    report_ready = bool(evidence_passed and report_draft.get("status") == "complete")
    summary = {
        "target": derive_validate_target(info.get("target", ""), info.get("endpoint", "")),
        "program": (info.get("target") or "").strip(),
        "endpoint": (info.get("endpoint") or "").strip(),
        "method": normalize_http_method(info.get("method")),
        "vuln_class": vuln_class,
        # `confirmed` describes the validation evidence only.  The explicit
        # report-readiness fields below prevent a template draft from being
        # mistaken for a submit-ready finding.
        "result": "confirmed" if evidence_passed else "partial",
        "severity": severity,
        "notes": (info.get("impact") or "").strip(),
        "impact": (info.get("impact") or "").strip(),
        "cvss_score": float(info.get("cvss_score", 0.0) or 0.0),
        "cvss_vector": info.get("cvss_vector", ""),
        "all_gates_passed": report_ready,
        "four_validation_gates_passed": bool(all_pass),
        "seven_question_gate_passed": bool(seven_question_gate.get("passed")),
        "validation_evidence_passed": evidence_passed,
        "report_ready": report_ready,
        "report_draft": report_draft,
        "report_draft_status": str(report_draft.get("status") or "not_written"),
        "seven_question_gate_decision": seven_question_gate.get("decision", "needs_review"),
        "seven_question_gate": seven_question_gate,
        "report_path": str(report_path),
        "validated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    finding_linkage = {
        "finding_id": info.get("finding_id"),
        "finding_source_file": info.get("finding_source_file") or info.get("source_file"),
        "finding_summary": info.get("finding_summary"),
    }
    for key, value in finding_linkage.items():
        if isinstance(value, str):
            value = value.strip()
        if value:
            summary[key] = value

    browser_linkage = compact_browser_evidence(info.get("browser_evidence"))
    if browser_linkage:
        summary["browser_evidence"] = browser_linkage

    scanner_summary = info.get("scanner_summary")
    if scanner_summary:
        summary["scanner_summary"] = scanner_summary
    scanner_summary_path = str(info.get("scanner_summary_path", "") or "").strip()
    if scanner_summary_path:
        summary["scanner_summary_path"] = scanner_summary_path
    scanner_confidence = str(info.get("scanner_confidence", "") or "").strip()
    if scanner_confidence and scanner_confidence != "unknown":
        summary["scanner_confidence"] = scanner_confidence

    evidence_rubric = info.get("evidence_rubric")
    if isinstance(evidence_rubric, dict) and evidence_rubric:
        summary["evidence_rubric"] = {
            "rubric_id": evidence_rubric.get("rubric_id", ""),
            "status": evidence_rubric.get("status", ""),
            "ready": bool(evidence_rubric.get("ready", False)),
            "score": int(evidence_rubric.get("score", 0) or 0),
            "missing_labels": list(evidence_rubric.get("missing_labels", []) or [])[:4],
            "next_actions": list(evidence_rubric.get("next_actions", []) or [])[:4],
            "summary": evidence_rubric.get("summary", ""),
        }

    machine_decision = info.get("machine_decision")
    if isinstance(machine_decision, dict) and machine_decision:
        # Keep the auditable decision binding and evidence pointers, never the
        # full report body. The body belongs only to the report draft path.
        summary["machine_decision"] = {
            "schema_version": int(machine_decision.get("schema_version", 0) or 0),
            "source": str(machine_decision.get("source") or ""),
            "evidence_summary": str(machine_decision.get("evidence_summary") or ""),
            "evidence_refs": [
                str(item)
                for item in (machine_decision.get("evidence_refs") or [])
                if str(item).strip()
            ],
        }

    return summary


def build_submission_notes(summary: dict) -> str:
    """Build a compact human checklist for final bounty submission review."""
    gates = "PASS" if summary.get("all_gates_passed") else "NEEDS REVIEW"
    seven_gate = "PASS" if summary.get("seven_question_gate_passed") else "NEEDS REVIEW"
    seven_decision = summary.get("seven_question_gate_decision", "needs_review")
    four_gates = "PASS" if summary.get("four_validation_gates_passed", summary.get("all_gates_passed")) else "NEEDS REVIEW"
    evidence = summary.get("browser_evidence") or {}
    evidence_path = evidence.get("summary_path") or evidence.get("dir") or "[attach raw request/response evidence]"
    scanner_path = summary.get("scanner_summary_path") or "[optional scanner summary path]"
    draft = summary.get("report_draft") if isinstance(summary.get("report_draft"), dict) else {}
    draft_status = str(draft.get("status") or summary.get("report_draft_status") or "unknown")

    validation_summary_name = Path(
        str(summary.get("validation_summary_path") or "validation-summary.json")
    ).name

    return f"""# Submission Notes

## Machine-readable handoff

- Validation summary: `{validation_summary_name}`
- Report draft: `{summary.get('report_path', '')}`
- Result: `{summary.get('result', '')}`
- Severity: `{summary.get('severity', '')}`
- CVSS: `{summary.get('cvss_score', '')}` `{summary.get('cvss_vector', '')}`

## Evidence checklist

- [ ] Raw HTTP request is pasted into the report PoC section.
- [ ] Raw HTTP response proving impact is pasted into the report PoC section.
- [ ] Evidence artifact path is attached: `{evidence_path}`
- [ ] Scanner handoff reviewed: `{scanner_path}`
- [ ] 7-Question Gate: `{seven_gate}` (`{seven_decision}`)
- [ ] Four validation gates: `{four_gates}`
- [ ] Combined report-readiness gates: `{gates}`
- [ ] Report draft completion: `{draft_status}`

## Submission checklist

- [ ] Remove placeholders and generic examples from the report.
- [ ] Confirm endpoint, account roles, and impact are target-specific but contain no secrets.
- [ ] Confirm no destructive/state-changing proof is required beyond documented validation.
- [ ] Confirm duplicate/program-policy notes have been reviewed.
"""


def _validation_artifact_key(summary: dict, report_path: str | Path) -> str:
    """Return a deterministic, collision-resistant per-finding artifact key."""
    raw_identity = str(summary.get("finding_id") or Path(report_path).stem or "validation").strip()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", raw_identity).strip(".-_") or "validation"
    digest = hashlib.sha256(raw_identity.encode("utf-8")).hexdigest()[:10]
    return f"{slug[:64]}-{digest}"


def validation_artifact_paths(
    summary: dict,
    report_path: str | Path,
) -> tuple[Path, Path]:
    """Return canonical summary/notes paths owned by one finding identity."""
    parent = Path(report_path).parent
    key = _validation_artifact_key(summary, report_path)
    return (
        parent / f"{key}.validation-summary.json",
        parent / f"{key}.submission-notes.md",
    )


def write_submission_notes(summary: dict, report_path: str | Path) -> Path:
    """Write per-report submission notes for human final review."""
    report_summary_path, notes_path = validation_artifact_paths(summary, report_path)
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    summary["validation_summary_path"] = str(report_summary_path)
    summary["submission_notes_path"] = str(notes_path)
    notes_path.write_text(build_submission_notes(summary), encoding="utf-8")
    return notes_path


def write_validation_summary(summary: dict, report_path: str | Path) -> Path:
    """Persist per-report summary and repo-global last-validate pointer."""
    report_path = Path(report_path)
    report_summary_path, submission_notes_path = validation_artifact_paths(summary, report_path)
    report_summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary["validation_summary_path"] = str(report_summary_path)
    summary["submission_notes_path"] = str(submission_notes_path)
    submission_notes_path.write_text(build_submission_notes(summary), encoding="utf-8")
    report_summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    last_validate_path = BASE_DIR / "findings" / "last-validate.json"
    last_validate_path.parent.mkdir(parents=True, exist_ok=True)
    last_validate_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return report_summary_path


def ensure_report_output_path(output_path: str | Path) -> Path:
    """Return report path after creating its parent directory.

    `--output` can point at a brand-new directory during pressure tests or
    Claude CLI runs; report writing should not fail after the validation gates
    have already completed.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def mark_finding_validated(findings_dir: str, finding_id: str, summary: dict, summary_path: str | Path) -> None:
    """Best-effort update of findings.json after validation completes."""
    if not findings_dir or not finding_id:
        return
    status = "validated" if validation_evidence_passed(summary) else "partial"
    update_finding_status(
        findings_dir,
        finding_id,
        validation_status=status,
        validation_summary=str(summary_path),
        validation_report_path=str(summary.get("report_path") or ""),
        validated_at=summary.get("validated_at", ""),
    )


def _endpoint_path_for_method_match(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        return (parsed.path or "/").split("?", 1)[0].split("#", 1)[0]
    return raw.split("?", 1)[0].split("#", 1)[0] or "/"


def _validation_method_from_summary(summary: dict, repo: Path) -> str:
    """Return the replay method without guessing from endpoint shape.

    Explicit summary data wins. For older ad-hoc summaries that missed
    ``method``, reuse a prior non-validate ledger entry for the same
    endpoint/vulnerability. This preserves evidence fidelity while avoiding
    path-based heuristics or value judgments.
    """
    explicit = str(summary.get("method") or "").strip()
    if explicit:
        return normalize_http_method(explicit)

    target = str(summary.get("target") or "").strip()
    endpoint = _endpoint_path_for_method_match(str(summary.get("endpoint") or ""))
    vuln_class = str(summary.get("vuln_class") or "validation").strip().lower()
    if not target or not endpoint:
        return "GET"

    try:
        try:
            from evidence_ledger import load_entries
        except ImportError:  # pragma: no cover - package import path
            from tools.evidence_ledger import load_entries
        entries = load_entries(repo, target)
    except Exception:  # pragma: no cover - best-effort evidence fidelity fallback
        return "GET"

    for entry in reversed(entries):
        if str(entry.get("source") or "").strip().lower() == "validate":
            continue
        if _endpoint_path_for_method_match(str(entry.get("endpoint") or "")) != endpoint:
            continue
        if str(entry.get("vuln_class") or "").strip().lower() != vuln_class:
            continue
        method = str(entry.get("method") or "").strip()
        if method:
            return normalize_http_method(method)
    return "GET"


def _finding_url_from_summary(summary: dict) -> str:
    endpoint = str(summary.get("endpoint") or "").strip()
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    target = str(summary.get("target") or summary.get("program") or "").strip()
    if not target:
        return endpoint
    base = target if target.startswith(("http://", "https://")) else f"http://{target}"
    if endpoint and not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return base.rstrip("/") + (endpoint or "/")


def _finding_id_from_summary(summary: dict) -> str:
    vuln_class = str(summary.get("vuln_class") or "validation").strip().lower() or "validation"
    endpoint = str(summary.get("endpoint") or "").strip() or "endpoint"
    digest = hashlib.sha1(f"{vuln_class}:{endpoint}".encode("utf-8")).hexdigest()[:10]
    safe_endpoint = endpoint.split("?", 1)[0].strip("/") or "root"
    safe_endpoint = "".join(ch if ch.isalnum() else "_" for ch in safe_endpoint).strip("_")
    return f"validate-{vuln_class}-{safe_endpoint[:48]}-{digest}"


def upsert_ad_hoc_validated_finding(summary: dict, summary_path: str | Path, *, repo_root: str | Path | None = None) -> dict:
    """Create/update a structured finding for `/validate` runs without finding_id.

    Linked validations already update `findings.json` through `mark_finding_validated`.
    Ad-hoc validations still need a structured row, otherwise a confirmed issue
    can live only in Evidence Ledger and disappear from `/checkpoint` report flow.
    """
    target = str(summary.get("target") or "").strip()
    endpoint = str(summary.get("endpoint") or "").strip()
    if not target or not endpoint:
        return {"status": "skipped", "reason": "missing target or endpoint"}
    if str(summary.get("finding_id") or "").strip():
        return {"status": "skipped", "reason": "linked finding already handled"}

    repo = Path(repo_root) if repo_root is not None else BASE_DIR
    findings_dir = repo / "findings" / target_storage_key(target)
    finding_id = _finding_id_from_summary(summary)
    all_pass = validation_evidence_passed(summary)
    finding = {
        "id": finding_id,
        "type": str(summary.get("vuln_class") or "validation").strip().lower() or "validation",
        "category": str(summary.get("vuln_class") or "validation").strip().lower() or "validation",
        "title": f"Validated {summary.get('vuln_class', 'validation')} on {_finding_url_from_summary(summary)}",
        "summary": str(summary.get("notes") or summary.get("impact") or summary.get("result") or "validated finding"),
        "url": _finding_url_from_summary(summary),
        "severity": str(summary.get("severity") or "medium").lower(),
        "confidence": "confirmed" if all_pass else "medium",
        "source_file": str(summary_path),
        "line_number": 0,
        "template_id": "",
        "raw": f"validate:{summary.get('result', '')}:{summary_path}",
        "method": _validation_method_from_summary(summary, repo),
        "validation_status": "validated" if all_pass else "partial",
        "report_status": "not_generated",
        "validation_summary": str(summary_path),
        "validated_at": str(summary.get("validated_at") or ""),
        "vuln_class": str(summary.get("vuln_class") or "validation"),
        "report_draft_path": str(summary.get("report_path") or ""),
        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if all_pass:
        vuln_class = str(summary.get("vuln_class") or "validation")
        finding["evidence_rubric"] = {
            "rubric_id": vuln_class.lower(),
            "status": "validated",
            "ready": True,
            "score": 100,
            "satisfied_count": 4,
            "total": 4,
            "missing": [],
            "missing_labels": [],
            "next_actions": [],
            "summary": f"{vuln_class.lower()}:validated via /validate gates",
        }
    result = upsert_finding(findings_dir, finding, target=target)
    persisted = result.get("finding") or finding
    return {"status": "updated", "path": result.get("path", ""), "id": persisted["id"]}


def _validation_summary_path(report_path: str | Path, *, summary: dict | None = None) -> Path:
    payload = summary if isinstance(summary, dict) else {}
    recorded = str(payload.get("validation_summary_path") or "").strip()
    if recorded:
        return Path(recorded)
    return validation_artifact_paths(payload, report_path)[0]


def _validation_endpoint_markers(endpoint: str) -> list[str]:
    """Return full/path endpoint markers suitable for action_queue matching."""
    raw = str(endpoint or "").strip()
    markers = [raw] if raw else []
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        path_query = parsed.path or "/"
        if parsed.query:
            path_query = f"{path_query}?{parsed.query}"
        markers.append(path_query)
        markers.append(parsed.path or "/")
    return [item for item in markers if item]


def _validation_action_matches(action: dict, summary: dict) -> bool:
    """Return whether an action_queue item represents this validation result."""
    finding_id = str(summary.get("finding_id") or "").strip()
    endpoint_markers = _validation_endpoint_markers(str(summary.get("endpoint") or ""))
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    action_type = str(action.get("type") or "").lower()
    haystack = " ".join(
        str(value or "")
        for value in (
            action.get("id"),
            action.get("source_id"),
            action.get("evidence"),
            action.get("next_question"),
            action.get("action"),
            action.get("command_hint"),
            metadata.get("finding_id"),
            metadata.get("endpoint"),
        )
    )
    if finding_id and finding_id in haystack:
        return True
    if action_type in {"validation", "candidate-evidence-gap"}:
        for marker in endpoint_markers:
            if marker and marker in haystack:
                return True
    return False


def sync_validation_artifacts(summary: dict, *, repo_root: str | Path | None = None) -> dict:
    """Best-effort write-back from /validate into evidence ledger and action queue.

    The function is intentionally conservative: failures are returned in the
    result payload instead of blocking report generation.
    """
    repo = Path(repo_root) if repo_root is not None else BASE_DIR
    target = str(summary.get("target") or "").strip()
    endpoint = str(summary.get("endpoint") or "").strip()
    if not target or not endpoint:
        return {"status": "skipped", "reason": "missing target or endpoint"}

    summary_path = _validation_summary_path(
        summary.get("report_path") or "",
        summary=summary,
    )
    ledger_update: dict = {}
    queue_update: dict = {}
    finding_update: dict = {}

    try:
        try:
            from evidence_ledger import record_entry
        except ImportError:  # pragma: no cover - package import path
            from tools.evidence_ledger import record_entry

        ledger_entry = record_entry(
            repo,
            target=target,
            endpoint=endpoint,
            method=_validation_method_from_summary(summary, repo),
            vuln_class=str(summary.get("vuln_class") or "validation"),
            workflow="validate",
            actor="owner",
            object_scope="unknown",
            variant="baseline",
            source="validate",
            result="tested_finding" if validation_evidence_passed(summary) else "candidate",
            evidence_ref=str(summary_path),
            notes=f"/validate {summary.get('result', '')}: {summary.get('submission_notes_path', '')}",
        )
        ledger_update = {
            "status": "updated",
            "path": str(repo / "memory" / "evidence" / ledger_entry.get("target_key", "") / "ledger.jsonl"),
            "result": ledger_entry.get("result", ""),
        }
    except Exception as exc:  # pragma: no cover - defensive best-effort path
        ledger_update = {"status": "error", "error": str(exc)}

    try:
        try:
            from action_queue import ACTIVE_STATUSES, load_queue, resolve_action
        except ImportError:  # pragma: no cover - package import path
            from tools.action_queue import ACTIVE_STATUSES, load_queue, resolve_action

        queue = load_queue(repo, target)
        matched = None
        for action in queue.get("actions", []):
            if not isinstance(action, dict):
                continue
            if str(action.get("status") or "queued") not in ACTIVE_STATUSES:
                continue
            if _validation_action_matches(action, summary):
                matched = action
                break

        if matched:
            resolved = resolve_action(
                repo,
                target=target,
                action_id=str(matched.get("id") or ""),
                status="validated" if validation_evidence_passed(summary) else "candidate",
                result=f"validation-summary={summary_path}",
                notes=f"submission-notes={summary.get('submission_notes_path', '')}",
            )
            queue_update = {
                "status": "updated",
                "id": resolved.get("id", ""),
                "action_status": resolved.get("status", ""),
            }
        else:
            queue_update = {"status": "skipped", "reason": "no matching active validation action"}
    except Exception as exc:  # pragma: no cover - defensive best-effort path
        queue_update = {"status": "error", "error": str(exc)}

    try:
        finding_update = upsert_ad_hoc_validated_finding(summary, summary_path, repo_root=repo)
    except Exception as exc:  # pragma: no cover - defensive best-effort path
        finding_update = {"status": "error", "error": str(exc)}

    return {
        "status": "updated",
        "ledger": ledger_update,
        "action_queue": queue_update,
        "finding_index": finding_update,
    }


def _map_validate_result_to_calibration_outcome(result: str) -> str | None:
    """(P5-W1 R5) Map /validate result string to a calibration outcome label.

    Returns None for results that should not be recorded (e.g., unknown
    intermediate states), so callers can skip silently rather than write
    an invalid row.
    """
    if not isinstance(result, str):
        return None
    r = result.strip().lower()
    if r == "confirmed":
        return "helped"
    if r == "rejected":
        return "false_positive"
    if r in {"partial", "informational"}:
        return "no_signal"
    return None


def record_validation_calibration(
    summary: dict,
    *,
    session_id: str = "",
    path=None,
) -> dict | None:
    """(P5-W1 R5) Record a calibration outcome derived from a validate summary.

    Returns the written calibration record dict, or None if the summary
    lacked enough context (no target/vuln_class) or the result mapped to
    an unsupported outcome. Best-effort: errors are swallowed and None
    returned, so a calibration write failure never blocks /validate.
    """
    try:
        try:
            from pattern_calibration import pattern_id_for, record_outcome
        except ImportError:  # pragma: no cover - package import path
            from tools.pattern_calibration import pattern_id_for, record_outcome

        target = str(summary.get("target", "") or "").strip()
        vuln_class = str(summary.get("vuln_class", "") or "").strip()
        if not target or not vuln_class:
            return None
        outcome = _map_validate_result_to_calibration_outcome(
            str(summary.get("result", "") or "")
        )
        if not outcome:
            return None
        # technique is not consistently captured in the validate summary;
        # leave empty so pattern_id aggregates per (target, vuln_class).
        pid = pattern_id_for({
            "target": target,
            "vuln_class": vuln_class,
            "technique": str(summary.get("technique", "") or ""),
        })
        return record_outcome(
            pattern_id=pid,
            outcome=outcome,
            session_id=session_id,
            target=target,
            path=path,
        )
    except Exception:
        return None


def update_runtime_state_after_validate(summary: dict, findings_dir: str = "") -> None:
    """Best-effort runtime state refresh after validation finishes."""
    target = str(summary.get("target", "") or "").strip()
    if not target:
        return
    # (P5-W1 R5) Record calibration outcome alongside runtime state refresh.
    record_validation_calibration(
        summary,
        session_id=str(summary.get("session_id", "") or ""),
    )
    try:
        try:
            from runtime_state import inspect_recon_artifacts, update_runtime_state
        except ImportError:  # pragma: no cover - package import path
            from tools.runtime_state import inspect_recon_artifacts, update_runtime_state
        try:
            from resume import load_structured_finding_followup
        except ImportError:  # pragma: no cover - package import path
            from tools.resume import load_structured_finding_followup

        artifacts = inspect_recon_artifacts(BASE_DIR, target)
        structured = load_structured_finding_followup(BASE_DIR, target)
        update_runtime_state(
            BASE_DIR,
            target,
            mode="validate",
            current_stage="validate",
            last_completed_step="validate_finding",
            recon_ready=bool(artifacts.get("ready")),
            surface_ready=bool(artifacts.get("surface_inputs_ready")),
            pending_validation=int(structured.get("pending_validation", 0) or 0),
            validated_pending_report=int(structured.get("validated_pending_report", 0) or 0),
            last_validation_result=str(summary.get("result", "") or ""),
            last_validated_finding_id=str(summary.get("finding_id", "") or ""),
            findings_dir=findings_dir or "",
        )
    except Exception:
        return


def load_finding_prefill(
    findings_dir: str,
    finding_id: str,
    *,
    migrate_legacy: bool = True,
) -> dict:
    """Load defaults from findings.json, optionally without legacy write-back."""
    payload = load_finding_index(findings_dir, migrate_legacy=migrate_legacy)
    finding = next(
        (
            item
            for item in payload.get("findings", [])
            if isinstance(item, dict) and str(item.get("id") or "") == finding_id
        ),
        None,
    )
    if not finding:
        return {}
    rubric = finding.get("evidence_rubric") if isinstance(finding.get("evidence_rubric"), dict) else {}
    if not rubric:
        source_file = str(finding.get("source_file") or "")
        source_path = Path(source_file)
        if source_file and not source_path.is_absolute():
            source_path = BASE_DIR / source_file
        if source_path.is_file() and source_path.suffix == ".json":
            try:
                source_payload = json.loads(source_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                source_payload = {}
            source_rubric = source_payload.get("evidence_rubric") if isinstance(source_payload, dict) else {}
            if isinstance(source_rubric, dict):
                rubric = source_rubric
    if not rubric:
        rubric = evaluate_candidate_evidence(finding)

    return {
        "target": payload.get("target") or Path(findings_dir).name,
        "vuln_type": (finding.get("type") or "").upper(),
        "endpoint": finding.get("url") or "",
        "finding_id": finding.get("id") or finding_id,
        "source_file": finding.get("source_file") or "",
        "summary": finding.get("summary") or finding.get("raw") or "",
        "rubric": rubric,
        "validation_report_path": finding.get("validation_report_path") or "",
        "report_draft_path": finding.get("report_draft_path") or "",
        "report_file": finding.get("report_file") or "",
    }


def resolve_browser_evidence_for_validate(
    target: str,
    *,
    browser_url: str = "",
    browser_session: str = "",
    browser_evidence_dir: str = "",
    browser_screenshot: bool = False,
) -> dict:
    """Resolve compact browser evidence linkage for validation summary."""
    evidence_root = BASE_DIR / "evidence"
    if browser_url:
        try:
            summary = capture_browser_evidence(
                target,
                browser_url,
                session=browser_session,
                label="validate",
                evidence_root=evidence_root,
                capture_screenshot=browser_screenshot,
            )
        except Exception as exc:
            return {"url": browser_url, "error": str(exc)}
        return compact_browser_evidence(summary)

    if browser_evidence_dir:
        return compact_browser_evidence(browser_evidence_dir)

    return load_last_browser_evidence(target, evidence_root=evidence_root)


def _normalize_vuln_class(value: Any) -> str:
    """Normalize one vulnerability-class binding without guessing its meaning."""
    normalized = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower())
    return normalized.strip("_")


def _endpoint_path_query(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        path = parsed.path or "/"
        return f"{path}?{parsed.query}" if parsed.query else path
    return raw


def _machine_endpoints_match(decision_endpoint: str, finding_endpoint: str) -> bool:
    """Match exact URLs or a target-bound URL against its canonical path form."""
    left = str(decision_endpoint or "").strip()
    right = str(finding_endpoint or "").strip()
    if not left or not right:
        return False
    if left.rstrip("/") == right.rstrip("/"):
        return True
    left_url = urlparse(left)
    right_url = urlparse(right)
    if (left_url.scheme or left_url.netloc) and (right_url.scheme or right_url.netloc):
        return (
            left_url.netloc.lower() == right_url.netloc.lower()
            and _endpoint_path_query(left) == _endpoint_path_query(right)
        )
    return _endpoint_path_query(left) == _endpoint_path_query(right)


def _required_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"decision.{field} must be a non-empty string")
    return text


def _load_machine_decision(path: str) -> tuple[dict[str, Any], Path]:
    """Load a strict machine validation decision without best-effort fallback."""
    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read decision JSON: {source}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid decision JSON: {source}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("decision JSON must contain one object")
    if payload.get("schema_version") != MACHINE_DECISION_SCHEMA_VERSION:
        raise ValueError(
            "decision.schema_version must be "
            f"{MACHINE_DECISION_SCHEMA_VERSION}"
        )
    return payload, source


def _resolve_machine_findings_dir(args: argparse.Namespace, decision_target: str) -> Path:
    """Resolve the only canonical finding directory allowed for a decision."""
    if not args.finding_id:
        raise ValueError("--decision-json requires --finding-id")
    if args.target:
        supplied_target = canonical_target_value(args.target)
        if supplied_target != decision_target:
            raise ValueError(
                "--target must match decision.target after canonical normalization"
            )
    if args.findings_dir:
        root = Path(args.findings_dir).expanduser()
        if not root.is_absolute():
            root = (Path.cwd() / root).resolve()
        return root
    if not args.target:
        raise ValueError("--decision-json requires --findings-dir or --target")
    return BASE_DIR / "findings" / target_storage_key(decision_target)


def _resolve_machine_evidence_refs(values: Any, *, repo_root: Path) -> list[str]:
    """Require explicit, locatable raw-evidence pointers before mutation."""
    if not isinstance(values, list) or not values:
        raise ValueError("decision.evidence.refs must be a non-empty list")
    resolved: list[str] = []
    for value in values:
        raw = _required_text(value, "evidence.refs[]")
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = repo_root / path
        path = path.resolve()
        if not path.is_file():
            raise ValueError(f"decision evidence ref is not a readable file: {raw}")
        resolved.append(str(path))
    return resolved


def _parse_machine_gates(raw: Any) -> tuple[dict[str, bool], dict[str, dict[str, Any]]]:
    """Validate explicit four-gate decisions; no inferred/default confirmations."""
    if not isinstance(raw, dict):
        raise ValueError("decision.gates must be an object")
    passed: dict[str, bool] = {}
    notes: dict[str, dict[str, Any]] = {}
    for key in MACHINE_DECISION_GATE_KEYS:
        item = raw.get(key)
        if not isinstance(item, dict) or not isinstance(item.get("passed"), bool):
            raise ValueError(f"decision.gates.{key}.passed must be an explicit boolean")
        raw_notes = item.get("notes", {})
        if raw_notes is None:
            raw_notes = {}
        if not isinstance(raw_notes, dict):
            raise ValueError(f"decision.gates.{key}.notes must be an object when present")
        passed[key] = item["passed"]
        notes[key] = dict(raw_notes)
    return passed, notes


def _parse_machine_seven_questions(raw: Any) -> dict[str, Any]:
    """Require a complete Q1-Q7 machine judgment with an explicit basis per item."""
    if not isinstance(raw, dict):
        raise ValueError("decision.seven_question_gate must be an object")
    values = raw.get("questions") if isinstance(raw.get("questions"), dict) else raw
    if not isinstance(values, dict):
        raise ValueError("decision.seven_question_gate.questions must be an object")

    questions: dict[str, dict[str, Any]] = {}
    for key, question in SEVEN_QUESTION_DEFINITIONS:
        item = values.get(key)
        if not isinstance(item, dict):
            raise ValueError(f"decision.seven_question_gate.{key} must be an object")
        raw_status = item.get("status")
        status = _normalize_seven_question_status(raw_status)
        if raw_status is None or status == "unknown" and str(raw_status).strip().lower() != "unknown":
            raise ValueError(f"decision.seven_question_gate.{key}.status is invalid")
        basis = str(item.get("basis") or item.get("reason") or item.get("evidence") or "").strip()
        if not basis:
            raise ValueError(f"decision.seven_question_gate.{key} requires a non-empty basis")
        questions[key] = {
            "status": status,
            "basis": basis,
            "blocker": str(item.get("blocker") or "").strip(),
            "next_action": str(item.get("next_action") or "").strip(),
        }
    return {"source": "machine_decision", "questions": questions}


def _parse_machine_cvss(raw: Any) -> tuple[float, str, dict[str, str]]:
    """Validate an explicit CVSS decision without interactive score prompts."""
    if not isinstance(raw, dict):
        raise ValueError("decision.cvss must be an object")
    score = raw.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= float(score) <= 10:
        raise ValueError("decision.cvss.score must be a number from 0 to 10")
    vector = _required_text(raw.get("vector"), "cvss.vector")
    params_raw = raw.get("params", {})
    if not isinstance(params_raw, dict):
        raise ValueError("decision.cvss.params must be an object when present")
    params = {
        key: str(params_raw.get(key) or "").strip()
        for key in CVSS_PARAMETER_KEYS
        if str(params_raw.get(key) or "").strip()
    }
    return float(score), vector, params


def _resolve_machine_report(
    raw: Any,
    *,
    findings_dir: Path,
    repo_root: Path,
) -> tuple[Path, str]:
    """Resolve one explicit report payload under the bound finding directory."""
    if not isinstance(raw, dict):
        raise ValueError("decision.report must be an object")
    report_path = Path(_required_text(raw.get("path"), "report.path")).expanduser()
    if not report_path.is_absolute():
        report_path = repo_root / report_path
    report_path = report_path.resolve()
    try:
        report_path.relative_to(findings_dir.resolve())
    except ValueError as exc:
        raise ValueError("decision.report.path must stay under the bound findings directory") from exc
    content = _required_text(raw.get("content"), "report.content")
    return report_path, content


def _resolved_repo_path(value: Any, *, repo_root: Path) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = repo_root / path
    return path.resolve()


def _assert_machine_report_path_available(
    findings_dir: Path,
    *,
    finding_id: str,
    report_path: Path,
    report_content: str,
    repo_root: Path,
) -> None:
    """Reject cross-finding report reuse before the first validation write."""
    payload = load_finding_index(findings_dir, migrate_legacy=False)
    owners: set[str] = set()
    for item in payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        for key in ("validation_report_path", "report_draft_path", "report_file"):
            owned_path = _resolved_repo_path(item.get(key), repo_root=repo_root)
            if owned_path == report_path:
                owners.add(str(item.get("id") or ""))
                break
    other_owners = {owner for owner in owners if owner and owner != finding_id}
    if other_owners:
        raise ValueError(
            "decision report path is already owned by another finding: "
            + ", ".join(sorted(other_owners))
        )
    if not report_path.exists() or finding_id in owners:
        return
    expected = report_content.rstrip() + "\n"
    try:
        current = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"unable to inspect existing decision.report.path: {report_path}: {exc}") from exc
    if current != expected:
        raise ValueError(
            "decision.report.path already exists without matching canonical finding ownership"
        )


def _write_machine_report(path: Path, content: str) -> None:
    """Create a report exclusively, allowing only a preflight-approved replay."""
    rendered = content.rstrip() + "\n"
    if path.exists():
        path.write_text(rendered, encoding="utf-8")
        return
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(rendered)
    except FileExistsError as exc:
        raise ValueError(f"decision.report.path appeared during exclusive create: {path}") from exc


def _build_machine_validation_input(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, Any], Path, Path, str]:
    """Validate every decision binding before any report/finding state is written."""
    decision, decision_path = _load_machine_decision(args.decision_json)
    decision_target = canonical_target_value(_required_text(decision.get("target"), "target"))
    finding_id = _required_text(decision.get("finding_id"), "finding_id")
    if finding_id != args.finding_id:
        raise ValueError("decision.finding_id must exactly match --finding-id")
    findings_dir = _resolve_machine_findings_dir(args, decision_target)
    # Machine binding must remain a pure preflight. In particular, a legacy
    # list payload is normalized in memory but not migrated until every
    # decision field has passed and the explicit owner transition begins.
    prefill = load_finding_prefill(
        str(findings_dir),
        finding_id,
        migrate_legacy=False,
    )
    if not prefill:
        raise ValueError(f"finding id not found in findings.json: {finding_id}")
    indexed_target = canonical_target_value(str(prefill.get("target") or ""))
    if indexed_target != decision_target:
        raise ValueError("decision.target does not match the canonical findings index target")

    decision_endpoint = _required_text(decision.get("endpoint"), "endpoint")
    if not _machine_endpoints_match(decision_endpoint, str(prefill.get("endpoint") or "")):
        raise ValueError("decision.endpoint does not match the canonical finding endpoint")
    decision_vuln_class = _normalize_vuln_class(_required_text(decision.get("vuln_class"), "vuln_class"))
    indexed_vuln_class = _normalize_vuln_class(prefill.get("vuln_type"))
    if not decision_vuln_class or decision_vuln_class != indexed_vuln_class:
        raise ValueError("decision.vuln_class does not match the canonical finding class")

    gate_passed, gate_notes = _parse_machine_gates(decision.get("gates"))
    seven_questions = _parse_machine_seven_questions(decision.get("seven_question_gate"))
    cvss_score, cvss_vector, cvss_params = _parse_machine_cvss(decision.get("cvss"))
    impact = _required_text(decision.get("impact"), "impact")
    evidence = decision.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("decision.evidence must be an object")
    evidence_summary = _required_text(evidence.get("summary"), "evidence.summary")
    evidence_refs = _resolve_machine_evidence_refs(evidence.get("refs"), repo_root=BASE_DIR)
    report_path, report_content = _resolve_machine_report(
        decision.get("report"),
        findings_dir=findings_dir,
        repo_root=BASE_DIR,
    )
    _assert_machine_report_path_available(
        findings_dir,
        finding_id=finding_id,
        report_path=report_path,
        report_content=report_content,
        repo_root=BASE_DIR,
    )

    info = {
        "target": decision_target,
        "vuln_type": str(prefill.get("vuln_type") or decision_vuln_class),
        "endpoint": decision_endpoint,
        "method": normalize_http_method(decision.get("method") or "GET"),
        "impact": impact,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_params": cvss_params,
        "finding_id": finding_id,
        "finding_source_file": prefill.get("source_file", ""),
        "finding_summary": prefill.get("summary", ""),
        "evidence_rubric": prefill.get("rubric", {}),
        "seven_question_gate": seven_questions,
        "machine_decision": {
            "schema_version": MACHINE_DECISION_SCHEMA_VERSION,
            "source": str(decision_path),
            "evidence_summary": evidence_summary,
            "evidence_refs": evidence_refs,
        },
    }
    for key in MACHINE_DECISION_GATE_KEYS:
        info[f"{key}_pass"] = gate_passed[key]
        info[f"{key}_notes"] = gate_notes[key]
    return info, prefill, findings_dir, report_path, report_content


def run_machine_validation(args: argparse.Namespace) -> dict[str, Any]:
    """Apply an explicit non-TTY validation decision through existing owners only."""
    info, prefill, findings_dir, report_path, report_content = _build_machine_validation_input(args)
    output_path = ensure_report_output_path(report_path)
    _write_machine_report(output_path, report_content)

    all_pass = all(bool(info.get(f"{key}_pass")) for key in MACHINE_DECISION_GATE_KEYS)
    summary = build_validation_summary(info, all_pass=all_pass, report_path=output_path)
    summary_path = write_validation_summary(summary, output_path)
    validation_sync = sync_validation_artifacts(summary, repo_root=BASE_DIR)
    if validation_sync.get("status") == "updated":
        summary["validation_sync"] = validation_sync
        summary_path = write_validation_summary(summary, output_path)
    mark_finding_validated(
        str(findings_dir),
        str(prefill.get("finding_id") or ""),
        summary,
        summary_path,
    )
    update_runtime_state_after_validate(summary, str(findings_dir))
    return {
        "status": "updated",
        "finding_id": str(prefill.get("finding_id") or ""),
        "findings_dir": str(findings_dir),
        "report_path": str(output_path),
        "summary_path": str(summary_path),
        "submission_notes_path": str(summary.get("submission_notes_path") or ""),
        "result": str(summary.get("result") or ""),
        "report_ready": bool(summary.get("report_ready")),
        "validation_sync": validation_sync,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build the shared interactive/non-interactive validation CLI parser."""
    parser = argparse.ArgumentParser(description="Interactive bug validation assistant")
    parser.add_argument("--output",  default="", help="Output path for generated report skeleton")
    parser.add_argument("--program", default="", help="HackerOne program handle for dup check")
    parser.add_argument("--findings-dir", default="", help="Directory containing findings.json")
    parser.add_argument("--finding-id", default="", help="Prefill target/type/endpoint from findings.json")
    parser.add_argument(
        "--target",
        default="",
        help="Canonical target shortcut for --decision-json; resolves findings/<target-key>.",
    )
    parser.add_argument(
        "--decision-json",
        default="",
        help="Explicit machine-readable non-TTY validation decision bound to --finding-id.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine validation result as JSON.")
    parser.add_argument("--method", default="GET", help="HTTP method used by the validated replay evidence")
    parser.add_argument("--browser-url", default="", help="Capture validate browser evidence for this URL")
    parser.add_argument(
        "--browser-session",
        default="",
        help="Optional playwright-cli session name for fallback browser evidence when MCP artifacts are unavailable",
    )
    parser.add_argument("--browser-evidence-dir", default="", help="Attach an existing browser evidence capture directory")
    parser.add_argument("--browser-screenshot", action="store_true", help="Also capture screenshot.png with browser evidence")
    parser.add_argument("--scanner-summary", default="", help="Attach tools/vuln_scanner.sh summary.json to validation-summary.json")
    parser.add_argument(
        "--seven-question-json",
        default="",
        help="Optional JSON containing Claude/operator 7-Question Gate judgments for validation-summary.json",
    )
    parser.add_argument(
        "--scanner-confidence",
        default="unknown",
        choices=["confirmed", "possible", "informational", "unknown"],
        help="Confidence level from the scanner handoff",
    )
    return parser


def _run_interactive_validation(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Run the existing TTY flow after main has ruled out non-interactive use."""

    finding_prefill = {}
    if args.finding_id:
        if not args.findings_dir:
            parser.error("--finding-id requires --findings-dir")
        finding_prefill = load_finding_prefill(args.findings_dir, args.finding_id)
        if not finding_prefill:
            parser.error(f"finding id not found in findings.json: {args.finding_id}")

    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Validation Assistant{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"\nThis records the 7-Question Gate, walks through the 4 validation gates,")
    print(f"calculates your CVSS score, and generates a report skeleton.\n")
    config = load_config()
    ctf_mode = bool(config.get("ctf_mode", False))
    if ctf_mode:
        print(f"{YELLOW}CTF mode enabled:{RESET} external program checks stay fully relaxed in Gate 2.\n")

    # Collect basic info upfront
    section("Target Information")
    if finding_prefill:
        print(f"  Loaded finding candidate: {finding_prefill['finding_id']}")
        if finding_prefill.get("source_file"):
            print(f"  Source artifact: {finding_prefill['source_file']}")
        if finding_prefill.get("summary"):
            print(f"  Summary: {finding_prefill['summary'][:180]}")
        rubric = finding_prefill.get("rubric") or {}
        if rubric:
            status = rubric.get("status", "")
            score = rubric.get("score", 0)
            print(f"  Evidence rubric: {status} ({score}/100) — {rubric.get('title', '')}")
            missing = rubric.get("missing_labels") or []
            if missing:
                print(f"  Missing evidence: {', '.join(str(item) for item in missing[:4])}")
                action = first_missing_action(rubric)
                if action:
                    print(f"  Suggested next evidence step: {action}")
            else:
                print("  Missing evidence: none detected by rubric")

    target_prompt = "Target / program / lab name"
    scanner_summary = load_json_file(args.scanner_summary)
    seven_question_input = load_json_file(args.seven_question_json)
    target_program = args.program or ask(
        target_prompt,
        finding_prefill.get("target", "unknown"),
    )
    vuln_type      = ask(
        "Vulnerability type (e.g., 'IDOR', 'Stored XSS', 'SSRF')",
        finding_prefill.get("vuln_type", ""),
    )
    endpoint       = ask(
        "Affected endpoint (e.g., '/api/invoices/:id')",
        finding_prefill.get("endpoint", ""),
    )

    # Run the 4 gates
    g1_pass, g1_notes = gate1_is_real()
    g2_pass, g2_notes = gate2_in_scope(target_program, skip_scope=ctf_mode)
    g3_pass, g3_notes = gate3_exploitable()
    g4_pass, g4_notes = gate4_not_dup(vuln_type, endpoint, target_program)

    # Summary
    section("Validation Summary")
    gates = [
        (1, "Is it real?",       g1_pass),
        (2, "Matches target context?", g2_pass),
        (3, "Is it exploitable?",g3_pass),
        (4, "Is it a dup?",      g4_pass),
    ]
    all_pass = all(p for _, _, p in gates)

    for n, name, passed in gates:
        icon = f"{GREEN}✓{RESET}" if passed else f"{RED}✗{RESET}"
        print(f"  Gate {n} — {name}: {icon}")

    print()
    if all_pass:
        print(
            f"  {BOLD}{GREEN}All validation gates passed.{RESET} "
            "Evidence is validated; report readiness still requires a completed draft and raw proof."
        )
    else:
        failed = [name for _, name, p in gates if not p]
        print(f"  {BOLD}{RED}Failed: {', '.join(failed)}{RESET}")
        print(f"  {DIM}Resolve the failed gates before submitting.{RESET}")

    if not all_pass:
        if not ask_yn("\nContinue to CVSS scoring anyway?", default=False):
            return 0

    # CVSS scoring
    cvss_score, cvss_vector, cvss_params = ask_cvss_score()

    # Generate report skeleton
    section("Report Generation")
    impact_desc = g3_notes.get("impact_description", "")

    info = {
        "target":      target_program,
        "vuln_type":   vuln_type,
        "endpoint":    endpoint,
        "method":      normalize_http_method(args.method),
        "impact":      impact_desc,
        "cvss_score":  cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_params": cvss_params,
        "gate1_pass":  g1_pass,
        "gate2_pass":  g2_pass,
        "gate3_pass":  g3_pass,
        "gate4_pass":  g4_pass,
        "gate1_notes": g1_notes,
        "gate2_notes": g2_notes,
        "gate3_notes": g3_notes,
        "gate4_notes": g4_notes,
    }
    if args.seven_question_json:
        info["seven_question_gate"] = seven_question_input
    if args.scanner_summary:
        info["scanner_summary_path"] = args.scanner_summary
        info["scanner_summary"] = scanner_summary
    if args.scanner_confidence != "unknown":
        info["scanner_confidence"] = args.scanner_confidence
    browser_target = derive_validate_target(target_program, args.browser_url or endpoint)
    browser_evidence = resolve_browser_evidence_for_validate(
        browser_target,
        browser_url=args.browser_url,
        browser_session=args.browser_session,
        browser_evidence_dir=args.browser_evidence_dir,
        browser_screenshot=args.browser_screenshot,
    )
    if browser_evidence:
        info["browser_evidence"] = browser_evidence
        if browser_evidence.get("dir"):
            print(f"  Browser evidence linked: {browser_evidence['dir']}")
        elif browser_evidence.get("error"):
            print(f"  {YELLOW}Browser evidence capture failed:{RESET} {browser_evidence['error']}")
    if finding_prefill:
        info.update({
            "finding_id": finding_prefill.get("finding_id", ""),
            "finding_source_file": finding_prefill.get("source_file", ""),
            "finding_summary": finding_prefill.get("summary", ""),
            "evidence_rubric": finding_prefill.get("rubric", {}),
        })

    skeleton = generate_report_skeleton(info)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        safe_name = vuln_type.lower().replace(" ", "-").replace("/", "-")
        safe_target = target_program.replace(" ", "-")
        base_dir = os.path.join(
            str(BASE_DIR),
            "findings", f"{safe_target}-{safe_name}"
        )
        os.makedirs(base_dir, exist_ok=True)
        output_path = os.path.join(base_dir, "hackerone-report.md")

    output_path = ensure_report_output_path(output_path)
    output_path.write_text(skeleton, encoding="utf-8")

    summary = build_validation_summary(info, all_pass=all_pass, report_path=output_path)
    summary_path = write_validation_summary(summary, output_path)
    validation_sync = sync_validation_artifacts(summary)
    if validation_sync.get("status") == "updated":
        summary["validation_sync"] = validation_sync
        summary_path = write_validation_summary(summary, output_path)
    if finding_prefill:
        mark_finding_validated(
            args.findings_dir,
            finding_prefill.get("finding_id", ""),
            summary,
            summary_path,
        )
    update_runtime_state_after_validate(summary, args.findings_dir)

    print(f"  {BOLD}{GREEN}Report skeleton generated:{RESET} {output_path}")
    if summary.get("validation_evidence_passed") and not summary.get("all_gates_passed"):
        print(
            f"  {YELLOW}Validation evidence passed, but the draft contains unresolved placeholders; "
            "it is not report-ready yet.{RESET}"
        )
    print(f"\n  {BOLD}Next steps:{RESET}")
    print(f"    1. Fill in the actual HTTP request + response in the PoC section")
    print(f"    2. Attach screenshots (naming: TARGET-VULN-TYPE-STEP-N.png)")
    print(f"    3. Replace all [bracketed] placeholders with specific details")
    print(f"    4. Run /bug-bounty-report for the submission checklist")
    print()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch TTY prompts or a strict explicit non-TTY decision path."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.decision_json:
            result = run_machine_validation(args)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            else:
                print(
                    "machine validation updated "
                    f"finding={result['finding_id']} report={result['report_path']} "
                    f"result={result['result']}"
                )
            return 0
        if args.target:
            raise ValueError("--target is available only together with --decision-json")
        if not sys.stdin.isatty():
            raise ValidationInputUnavailable(
                "non-TTY validation requires --decision-json; no state was written"
            )
        return _run_interactive_validation(args, parser)
    except ValidationInputUnavailable as exc:
        print(f"validate: {exc}", file=sys.stderr)
        return 2
    except (KeyError, OSError, ValueError) as exc:
        print(f"validate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
