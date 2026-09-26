#!/usr/bin/env python3
"""
validate.py — Machine-decision validation backend.
Records the 7-Question report-readiness gate and four-gate decision bound to
an explicit --decision-json, through the canonical finding/evidence owners.

Usage:
  python3 tools/validate.py --target target.com --finding-id sqli_abc \
      --decision-json /tmp/validation-decision.json --json
  python3 tools/validate.py --target target.com --finding-id sqli_abc \
      --decision-json /tmp/validation-decision.json --preflight --json
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

try:
    from finding_index import _finding_backend_context
except ImportError:  # pragma: no cover - package import path
    from tools.finding_index import _finding_backend_context


try:
    from closure_resolver import canonical_vuln_class
except ImportError:  # pragma: no cover - package import path
    from tools.closure_resolver import canonical_vuln_class

try:
    from target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - package import path
    from tools.target_paths import (
        canonical_target_value,
        target_storage_key,
    )

try:
    from target_store import StoreError, runtime_store
except ImportError:  # pragma: no cover - package import path
    from tools.target_store import StoreError, runtime_store

try:
    from browser_evidence import (
        compact_browser_evidence,
        load_last_browser_evidence,
    )
except ImportError:  # pragma: no cover - package import path
    from tools.browser_evidence import (
        compact_browser_evidence,
        load_last_browser_evidence,
    )

try:
    from runtime_config import load_runtime_config
except ImportError:  # pragma: no cover - package import path
    from tools.runtime_config import load_runtime_config


BASE_DIR = Path(__file__).resolve().parent.parent


def _repo_root_from_findings_dir(findings_dir: str | Path) -> Path:
    """Resolve a per-target ``<repo>/findings/<target>`` directory to its repo."""
    path = Path(findings_dir).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    if path.parent.name != "findings":
        raise ValueError("--findings-dir must be a per-target <repo>/findings/<target> directory")
    return path.parent.parent


def _validation_repo_root(findings_dir: str | Path = "", *, strict: bool = False) -> Path:
    """Return the repository owning validation artifacts."""
    if not str(findings_dir or "").strip():
        return BASE_DIR
    try:
        return _repo_root_from_findings_dir(findings_dir)
    except ValueError:
        if strict:
            raise
        return BASE_DIR


def load_config(repo_root: str | Path | None = None) -> dict:
    """Load optional repo-local config.json for validation flags."""
    return load_runtime_config(Path(repo_root) if repo_root is not None else BASE_DIR)


def load_json_file(path: str) -> dict:
    """Best-effort 读取可选 JSON 交接文件，失败时记录警告但不中断验证流程。"""
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Warning: unable to load JSON file {path}: {exc}")
        return {"_path": path, "_load_error": str(exc)}


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
MACHINE_DECISION_SCHEMA_VERSION = 2
RUNNER_SUMMARY_SCHEMA_VERSION = 1
MACHINE_DECISION_GATE_KEYS = ("gate1", "gate2", "gate3", "gate4")
CVSS_PARAMETER_KEYS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


class ValidationInputUnavailable(RuntimeError):
    """Raised when an interactive validation prompt cannot safely read input."""


class MachineDecisionPreflightError(ValueError):
    """Raised when a read-only machine decision preflight finds invalid fields."""

    def __init__(self, errors: Sequence[str]):
        self.errors = tuple(str(error) for error in errors if str(error).strip())
        super().__init__("; ".join(self.errors))


class ValidationSyncError(RuntimeError):
    """Raised when owner write-back must be retried before lifecycle advance."""

    def __init__(self, result: dict[str, Any]):
        self.result = dict(result)
        reason = str(result.get("reason") or "validation owner sync failed")
        super().__init__(reason)


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

def severity_from_score(score: float) -> str:
    if score == 0.0:  return "NONE"
    if score < 4.0:   return "LOW"
    if score < 7.0:   return "MEDIUM"
    if score < 9.0:   return "HIGH"
    return "CRITICAL"

# ─── Report skeleton generator ────────────────────────────────────────────────

def generate_report_skeleton(info: dict) -> str:
    """Generate a HackerOne-style report skeleton."""
    vuln_type  = info.get("vuln_type", "VULN_TYPE")
    target     = info.get("target", "TARGET")
    endpoint   = info.get("endpoint", "ENDPOINT")
    impact     = info.get("impact", "IMPACT_DESCRIPTION")
    score      = info.get("cvss_score")
    vector     = info.get("cvss_vector", "")
    sev        = severity_from_score(float(score)) if score is not None else str(info.get("severity") or "MEDIUM").upper()
    date       = datetime.now().strftime("%Y-%m-%d")
    cvss_section = ""
    if score is not None or str(vector).strip():
        cvss_section = f"""
## CVSS (optional external delivery field)

**Vector:** `{vector}`
**Score:** {score} ({sev})
"""
    severity_display = (
        f"{sev} ({score}) — {vector}"
        if score is not None or str(vector).strip()
        else sev
    )

    return f"""# {vuln_type} on {endpoint} — [fill in specific impact]

> **Draft status:** validation evidence may be complete, but this document is not
> report-ready or submittable until all `[INSERT ...]`, `[PASTE ...]`, and other
> bracketed evidence placeholders below are replaced with target-specific proof.

**Program:** {target}
**Severity:** {severity_display}
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

{cvss_section}

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
    cvss_score = info.get("cvss_score")
    severity = str(info.get("severity") or "").strip().lower()
    if severity not in {"info", "low", "medium", "high", "critical"}:
        # Legacy direct callers may still provide only a score; machine
        # decisions always carry the canonical Finding severity above.
        if cvss_score is not None:
            severity = severity_from_score(float(cvss_score)).lower()
        else:
            severity = "medium"
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
    delivery_judgment = None
    if (info.get("machine_decision") or {}).get("store_command"):
        # Novelty and destination policy do not decide whether a boundary was violated.
        questions = seven_question_gate["questions"]
        evidence_passed = all(gate_info.get(f"gate{number}_pass") is True for number in (1, 2, 3)) and all(
            questions[key]["status"] == "pass"
            for key in ("q1_replayable_now", "q2_impact_demonstrated", "q3_target_context",
                        "q4_attacker_access", "q6_impact_beyond_possible")
        )
        exclusions = []
        if gate_info.get("gate4_pass") is False:
            exclusions.append("Gate 4: duplicate at the destination")
        for key in ("q5_not_known_behavior", "q7_not_never_submit"):
            if questions[key]["status"] == "fail":
                exclusions.append(f"{key}: {questions[key]['basis']}")
        delivery_judgment = {
            "status": "ineligible" if exclusions else "eligible" if report_ready else "deferred",
            "reason": "; ".join(exclusions) if exclusions else "report-ready" if report_ready else "validation/report gate incomplete",
        }
    # Linked validation belongs to the canonical Finding owner.  Ad-hoc
    # validation keeps endpoint-host compatibility because no owner index is
    # available to supply a stronger target identity.
    linked_target = str(info.get("target") or "").strip()
    summary_target = (
        linked_target
        if str(info.get("finding_id") or "").strip() and linked_target
        else derive_validate_target(info.get("target", ""), info.get("endpoint", ""))
    )
    summary = {
        "target": summary_target,
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
    if delivery_judgment is not None:
        summary["delivery_judgment"] = delivery_judgment
    if cvss_score is not None:
        summary["cvss_score"] = float(cvss_score)
        summary["cvss_vector"] = str(info.get("cvss_vector") or "")

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
            "runner_summary": str(machine_decision.get("runner_summary") or ""),
        }
        if "store_command" in machine_decision:
            summary["machine_decision"]["store_command"] = machine_decision["store_command"]
    # 源归因透传：calibration 回写要读 summary.source_knowledge_refs。
    adopted_sources = info.get("source_knowledge_refs")
    if isinstance(adopted_sources, list) and adopted_sources:
        summary["source_knowledge_refs"] = [str(item) for item in adopted_sources]

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
    cvss_line = ""
    if "cvss_score" in summary or str(summary.get("cvss_vector") or "").strip():
        cvss_line = (
            f"- CVSS: `{summary.get('cvss_score', '')}` "
            f"`{summary.get('cvss_vector', '')}`\n"
        )

    return f"""# Submission Notes

## Machine-readable handoff

- Validation summary: `{validation_summary_name}`
- Report draft: `{summary.get('report_path', '')}`
- Result: `{summary.get('result', '')}`
- Severity: `{summary.get('severity', '')}`
{cvss_line.rstrip()}

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


def write_validation_summary(
    summary: dict,
    report_path: str | Path,
    *,
    repo_root: str | Path | None = None,
) -> Path:
    """Persist per-report summary and the owning repo's last-validate pointer."""
    report_path = Path(report_path)
    report_summary_path, submission_notes_path = validation_artifact_paths(summary, report_path)
    report_summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary["validation_summary_path"] = str(report_summary_path)
    summary["submission_notes_path"] = str(submission_notes_path)
    submission_notes_path.write_text(build_submission_notes(summary), encoding="utf-8")
    report_summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    owner_root = Path(repo_root) if repo_root is not None else BASE_DIR
    last_validate_path = owner_root / "findings" / "last-validate.json"
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


def apply_validation_decision(summary: dict, *, repo_root: str | Path | None = None) -> dict:
    """Apply the validation decision through the target's active owner.

    Primary targets persist only the technical assessment and delivery decision
    here. Report publication and action completion remain separate commands.
    """
    repo = Path(repo_root) if repo_root is not None else BASE_DIR
    target = str(summary.get("target") or "").strip()
    endpoint = str(summary.get("endpoint") or "").strip()
    if not target or not endpoint:
        return {"status": "skipped", "reason": "missing target or endpoint"}
    runtime_store(repo, target)
    return _sync_primary_validation(summary, repo)


def sync_validation_artifacts(summary: dict, *, repo_root: str | Path | None = None) -> dict:
    """Apply saved explicit judgments through the same Store command."""
    return apply_validation_decision(summary, repo_root=repo_root)


def _sync_primary_validation(summary: dict[str, Any], repo: Path) -> dict[str, Any]:
    """Persist technical and delivery decisions in the target transaction store."""
    target = canonical_target_value(str(summary.get("target") or ""))
    finding_id = str(summary.get("finding_id") or "").strip()
    if not finding_id:
        return {"status": "error", "reason": "primary validation requires finding_id"}
    store = runtime_store(repo, target)
    try:
        finding = store.finding(finding_id)
    except StoreError as exc:
        return {"status": "error", "reason": f"primary finding missing: {exc}"}
    command = (summary.get("machine_decision") or {}).get("store_command")
    required = {"store_id", "assessment_id", "delivery_id", "expected_assessment", "expected_delivery", "evidence", "destination"}
    if not isinstance(command, dict) or command.keys() != required:
        return {"status": "error", "reason": "primary validation requires a preflight-bound store command; regenerate the decision scaffold"}
    if command["store_id"] != store.binding()["store_id"]:
        return {"status": "error", "reason": "primary validation command belongs to a different Store generation"}
    delivery_judgment = summary.get("delivery_judgment")
    if (not isinstance(delivery_judgment, dict) or delivery_judgment.keys() != {"status", "reason"}
            or not isinstance(delivery_judgment["status"], str)
            or delivery_judgment["status"] not in {"eligible", "ineligible", "deferred"}
            or not isinstance(delivery_judgment["reason"], str) or not delivery_judgment["reason"].strip()):
        return {"status": "error", "reason": "primary validation requires an explicit delivery judgment"}
    verdict = "confirmed" if validation_evidence_passed(summary) else "inconclusive"
    assessment_id = command["assessment_id"]
    reason = str(summary.get("notes") or summary.get("impact") or "Machine validation decision")
    try:
        assessment = store.assess(
            command_id=assessment_id, finding_id=finding_id, verdict=verdict,
            reason=reason, boundary=str(summary.get("endpoint") or finding.get("endpoint") or ""),
            impact=str(summary.get("impact") or ""), evidence=command["evidence"],
            actor="validate", expected_assessment=command["expected_assessment"],
        )
    except StoreError as exc:
        return {"status": "error", "reason": f"primary assessment rejected: {exc}"}
    destination = command["destination"]
    delivery_id = command["delivery_id"]
    delivery_status = delivery_judgment["status"]
    try:
        delivery = store.decide_delivery(
            command_id=delivery_id, finding_id=finding_id, assessment_id=assessment_id,
            destination=destination, status=delivery_status,
            reason=delivery_judgment["reason"],
            actor="validate", expected_decision=command["expected_delivery"],
        )
    except StoreError as exc:
        return {"status": "error", "reason": f"primary delivery decision rejected: {exc}"}
    return {
        "status": "deduplicated" if assessment.get("replayed") and delivery.get("replayed") else "updated",
        "assessment": {"id": assessment_id, "verdict": verdict},
        "delivery": {"id": delivery_id, "status": delivery_status},
    }


def _validation_sync_retry_result(
    sync: object,
    *,
    report_path: str | Path,
    summary_path: str | Path,
) -> dict[str, Any] | None:
    """Return a retry payload when any target owner rejected write-back."""
    if not isinstance(sync, dict):
        return {
            "status": "retry",
            "retry": True,
            "reason": "validation owner sync returned an invalid result",
            "report_path": str(report_path),
            "summary_path": str(summary_path),
            "validation_sync": {},
        }
    failed = str(sync.get("status") or "").strip().lower() in {"error", "partial"}
    if not failed:
        return None
    return {
        "status": "retry",
        "retry": True,
        "reason": str(sync.get("reason") or "validation owner sync failed; retry without advancing lifecycle"),
        "report_path": str(report_path),
        "summary_path": str(summary_path),
        "validation_sync": sync,
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
        written = record_outcome(
            pattern_id=pid,
            outcome=outcome,
            session_id=session_id,
            target=target,
            path=path,
        )
        # 源归因（记忆复核断点 C 修复）：经验被跨目标采用时，反馈必须记到
        # 被采用的来源上（PatternDB 复合 ID 或知识卡路径），否则源经验的
        # helped/false_positive 统计永远拿不到数据。当前 target 的复合 ID
        # 照记（本地模式行为不变），来源行额外追加。
        source_refs = summary.get("source_knowledge_refs")
        if isinstance(source_refs, list):
            for source_ref in source_refs:
                if isinstance(source_ref, str) and source_ref.strip() and source_ref != pid:
                    record_outcome(
                        pattern_id=source_ref.strip(),
                        outcome=outcome,
                        session_id=session_id,
                        target=target,
                        path=path,
                    )
        return written
    except Exception:
        return None


def update_runtime_state_after_validate(
    summary: dict,
    findings_dir: str = "",
    *,
    repo_root: str | Path | None = None,
) -> None:
    """Best-effort runtime state refresh after validation finishes."""
    target = str(summary.get("target", "") or "").strip()
    if not target:
        return
    owner_root = Path(repo_root) if repo_root is not None else _validation_repo_root(findings_dir)
    # (P5-W1 R5) Record calibration outcome alongside runtime state refresh.
    record_validation_calibration(
        summary,
        session_id=str(summary.get("session_id", "") or ""),
        path=owner_root / "hunt-memory" / "pattern_calibration.jsonl",
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

        artifacts = inspect_recon_artifacts(owner_root, target)
        structured = load_structured_finding_followup(owner_root, target)
        update_runtime_state(
            owner_root,
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
    include_canonical: bool = False,
    repo_root: str | Path | None = None,
    target: str | None = None,
) -> dict:
    """Load Store defaults without changing the Finding or its source material."""
    inferred_root, owner_target = _finding_backend_context(findings_dir, target)
    owner_root = Path(repo_root).resolve() if repo_root is not None else inferred_root
    if Path(findings_dir).resolve() != owner_root / "findings" / target_storage_key(owner_target):
        raise ValueError("findings directory does not match the selected target owner")
    store = runtime_store(owner_root, owner_target)
    finding = store.finding(finding_id)
    prefill = {
        "target": owner_target, "vuln_type": finding["family"], "endpoint": finding["endpoint"],
        "finding_id": finding_id, "summary": finding["claim"], "store_id": store.binding()["store_id"],
    }
    if include_canonical:
        prefill["_canonical_finding"] = finding
    return prefill


def resolve_browser_evidence_for_validate(
    target: str,
    *,
    browser_evidence_dir: str = "",
    repo_root: str | Path | None = None,
) -> dict:
    """关联已由 Chrome DevTools/Playwright MCP 导入的浏览器证据。"""
    owner_root = Path(repo_root) if repo_root is not None else BASE_DIR
    evidence_root = owner_root / "evidence"
    if browser_evidence_dir:
        browser_path = Path(browser_evidence_dir).expanduser()
        if not browser_path.is_absolute():
            browser_path = owner_root / browser_path
        return compact_browser_evidence(browser_path)

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
        return root.resolve()
    if not args.target:
        raise ValueError("--decision-json requires --findings-dir or --target")
    return BASE_DIR / "findings" / target_storage_key(decision_target)


def _machine_repo_root(findings_dir: Path, *, explicit_findings_dir: str = "") -> Path:
    """Return the repository bound to a machine validation invocation."""
    if explicit_findings_dir:
        return _repo_root_from_findings_dir(findings_dir)
    return BASE_DIR


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


def _parse_source_knowledge_refs(values: Any) -> list[str]:
    """Optional adopted-experience pointers for calibration attribution.

    接受两类值：知识卡相对路径（knowledge/cards/... 或 knowledge/candidates/...，
    必须真实存在，防笔误）或 PatternDB 复合 ID（含 '|' 的字符串原样保留）。
    其他形态一律拒绝——归因错误比缺省更糟。
    """
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError("decision.source_knowledge_refs must be a list")
    refs: list[str] = []
    for value in values:
        raw = _required_text(value, "source_knowledge_refs[]")
        if "|" in raw:
            refs.append(raw)
            continue
        path = Path(raw)
        if not path.is_absolute():
            path = BASE_DIR / path
        if not path.is_file():
            raise ValueError(
                f"decision.source_knowledge_refs names a missing card: {raw}"
            )
        refs.append(raw)
    return refs


def _resolve_machine_repo_file(value: Any, field: str, *, repo_root: Path) -> Path:
    raw = _required_text(value, field)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = repo_root / path
    path = path.resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ValueError(f"decision.{field} must stay under the repository root") from exc
    if not path.is_file():
        raise ValueError(f"decision.{field} is not a readable file: {raw}")
    return path


def _validate_machine_runner_witness(
    evidence: dict[str, Any],
    *,
    evidence_refs: list[str],
    decision_target: str,
    finding_id: str,
    decision_endpoint: str,
    decision_method: str,
    findings_dir: Path,
    prefill: dict[str, Any],
    repo_root: Path,
) -> tuple[Path, str]:
    """Require one owner-bound runner witness before machine validation writes."""
    summary_path = _resolve_machine_repo_file(
        evidence.get("runner_summary"),
        "evidence.runner_summary",
        repo_root=repo_root,
    )
    if summary_path not in {Path(ref).resolve() for ref in evidence_refs}:
        raise ValueError("decision.evidence.refs must include decision.evidence.runner_summary")
    try:
        runner = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"decision.evidence.runner_summary is invalid JSON: {exc.msg}") from exc
    if not isinstance(runner, dict):
        raise ValueError("decision.evidence.runner_summary must contain one object")
    store = runtime_store(repo_root, decision_target)
    if canonical_target_value(str(runner.get("target") or "")) != decision_target:
        raise ValueError("runner target does not match decision.target")
    if str(runner.get("finding_id") or "").strip() != finding_id:
        raise ValueError("runner finding_id does not match decision.finding_id")
    if runner.get("result") != "tested_finding" or runner.get("candidate_ready") is not True:
        raise ValueError("primary runner summary must be a candidate-ready tested_finding")
    operation_id = _required_text(runner.get("store_operation_id"), "evidence.runner_summary.store_operation_id")
    execution = store.execution(operation_id)
    if execution["outcome"] != "complete" or not execution.get("observations"):
        raise ValueError("complete primary runner evidence is required before machine validation")
    linked_steps = {ref["step"] for ref in prefill["_canonical_finding"]["evidence"]
                    if ref["operation_id"] == operation_id}
    if not any(item["step"] in linked_steps
               and _machine_endpoints_match(decision_endpoint, item["endpoint"])
               and normalize_http_method(item["method"]) == decision_method
               for item in execution["observations"]):
        raise ValueError("primary runner operation must bind this finding's endpoint and method")
    store.verify_operation(operation_id)
    return summary_path, operation_id


def _primary_validation_command(decision: dict, prefill: dict, operation_id: str) -> dict:
    """Bind one authored decision to its evidence and explicit judgment predecessors."""
    expected = decision.get("store_preconditions", {"assessment_id": None, "delivery_id": None})
    if not isinstance(expected, dict) or set(expected) != {"assessment_id", "delivery_id"}:
        raise ValueError("decision.store_preconditions requires assessment_id and delivery_id (IDs or null)")
    if any(value is not None and (not isinstance(value, str) or not value.strip()) for value in expected.values()):
        raise ValueError("decision.store_preconditions values must be IDs or null")
    finding = prefill["_canonical_finding"]
    evidence = [ref for ref in finding["evidence"] if ref["operation_id"] == operation_id]
    if not evidence:
        raise ValueError("primary validation operation is not linked to this finding")
    digest = hashlib.sha256(json.dumps(
        [prefill["store_id"], decision, evidence], ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    assessment_id, delivery_id = f"assessment:{digest}", f"delivery:{digest}"
    destination = "internal-review"
    current_assessment = (finding.get("assessment") or {}).get("id")
    current_delivery = next((item["id"] for item in finding["deliveries"]
                             if item["destination"] == destination), None)
    if current_assessment not in (expected["assessment_id"], assessment_id):
        raise ValueError("technical assessment changed; regenerate the scaffold before a new decision")
    if current_delivery not in (expected["delivery_id"], delivery_id):
        raise ValueError("delivery decision changed; regenerate the scaffold before a new decision")
    return {
        "store_id": prefill["store_id"], "assessment_id": assessment_id, "delivery_id": delivery_id,
        "expected_assessment": expected["assessment_id"], "expected_delivery": expected["delivery_id"],
        "destination": destination, "evidence": evidence,
    }


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


def _parse_machine_severity(raw: Any) -> str:
    severity = str(raw or "").strip().lower()
    if severity not in {"info", "low", "medium", "high", "critical"}:
        raise ValueError("decision.severity must be info, low, medium, high, or critical")
    return severity


def _parse_machine_cvss(raw: Any) -> tuple[float, str, dict[str, str]] | None:
    """Validate optional legacy CVSS metadata when a decision supplies it."""
    if raw is None:
        return None
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
        raise ValueError(
            "decision.report.path must stay under the bound findings directory — fix: "
            f"use {findings_dir.resolve()}/<finding-id>-report.md"
        ) from exc
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
    target: str | None = None,
    store_command: dict | None = None,
) -> None:
    """Allow only the same finding, decision and intact report to replay."""
    _, owner_target = _finding_backend_context(findings_dir, target)
    store = runtime_store(repo_root, owner_target)
    page = store.finding_page(limit=1000)
    while True:
        for finding in page["items"]:
            for report in finding.get("reports", []):
                if _resolved_repo_path(report.get("artifact_ref"), repo_root=repo_root) == report_path:
                    if (finding["id"] != finding_id or not store_command or report.get("stale")
                            or report["assessment_id"] != store_command["assessment_id"]
                            or report["delivery_id"] != store_command["delivery_id"]):
                        raise ValueError("registered report artifact is immutable; choose a separate draft path")
        if not page["has_more"]:
            break
        page = store.finding_page(limit=1000, cursor=page["next_cursor"])
    if not report_path.exists():
        return
    expected = (report_content.rstrip() + "\n").encode("utf-8")
    try:
        current = report_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"unable to inspect existing decision.report.path: {report_path}: {exc}") from exc
    if current != expected:
        raise ValueError(
            "decision.report.path already exists without matching canonical finding ownership"
        )


def _write_machine_report(path: Path, content: str) -> None:
    """Publish a complete report exclusively; identical retries never rewrite it."""
    rendered = (content.rstrip() + "\n").encode("utf-8")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != rendered:
                raise ValueError(f"decision.report.path exists with different bytes: {path}")
    finally:
        if temporary is not None:
            temporary.unlink()


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
    repo_root = _machine_repo_root(findings_dir, explicit_findings_dir=args.findings_dir)
    # Preflight reads only the existing Store and never imports legacy files.
    prefill = load_finding_prefill(
        str(findings_dir), finding_id, migrate_legacy=False, include_canonical=True,
        repo_root=repo_root, target=decision_target,
    )
    if not prefill:
        raise ValueError(f"finding id not found in Store: {finding_id}")
    indexed_target = canonical_target_value(str(prefill.get("target") or ""))
    if indexed_target != decision_target:
        raise ValueError("decision.target does not match the Store target")

    decision_endpoint = _required_text(decision.get("endpoint"), "endpoint")
    if not _machine_endpoints_match(decision_endpoint, str(prefill.get("endpoint") or "")):
        raise ValueError("decision.endpoint does not match the canonical finding endpoint")
    decision_vuln_class = _normalize_vuln_class(_required_text(decision.get("vuln_class"), "vuln_class"))
    indexed_vuln_class = _normalize_vuln_class(prefill.get("vuln_type"))
    # 与 preflight 同规则：closure 词汇 owner 归一后比较（scanner 词汇
    # auth_bypass 与 closure 词汇 Authz 是同一概念）；未知类回退裸比较。
    decision_canonical = canonical_vuln_class(decision_vuln_class)
    indexed_canonical = canonical_vuln_class(indexed_vuln_class)
    if decision_canonical and indexed_canonical:
        classes_match = decision_canonical == indexed_canonical
    else:
        classes_match = decision_vuln_class == indexed_vuln_class
    if not decision_vuln_class or not classes_match:
        raise ValueError("decision.vuln_class does not match the canonical finding class")

    gate_passed, gate_notes = _parse_machine_gates(decision.get("gates"))
    seven_questions = _parse_machine_seven_questions(decision.get("seven_question_gate"))
    _parse_machine_cvss(decision.get("cvss"))
    impact = _required_text(decision.get("impact"), "impact")
    canonical_severity = (prefill.get("_canonical_finding") or {}).get("severity") or "medium"
    severity = _parse_machine_severity(decision.get("severity", canonical_severity))
    decision_method = normalize_http_method(decision.get("method") or "GET")
    evidence = decision.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("decision.evidence must be an object")
    evidence_summary = _required_text(evidence.get("summary"), "evidence.summary")
    evidence_refs = _resolve_machine_evidence_refs(evidence.get("refs"), repo_root=repo_root)
    runner_summary_path, operation_id = _validate_machine_runner_witness(
        evidence,
        evidence_refs=evidence_refs,
        decision_target=decision_target,
        finding_id=finding_id,
        decision_endpoint=decision_endpoint,
        decision_method=decision_method,
        findings_dir=findings_dir,
        prefill=prefill,
        repo_root=repo_root,
    )
    store_command = _primary_validation_command(decision, prefill, operation_id) if operation_id else None
    report_path, report_content = _resolve_machine_report(
        decision.get("report"),
        findings_dir=findings_dir,
        repo_root=repo_root,
    )
    _assert_machine_report_path_available(
        findings_dir,
        finding_id=finding_id,
        report_path=report_path,
        report_content=report_content,
        repo_root=repo_root,
        target=decision_target,
        store_command=store_command,
    )

    info = {
        "target": decision_target,
        "vuln_type": str(prefill.get("vuln_type") or decision_vuln_class),
        "endpoint": decision_endpoint,
        "method": decision_method,
        "impact": impact,
        "severity": severity,
        "finding_id": finding_id,
        "finding_source_file": prefill.get("source_file", ""),
        "finding_summary": prefill.get("summary", ""),
        "seven_question_gate": seven_questions,
        # 源归因（记忆复核断点 C 修复）：AI 声明本次验证实际采用的经验来源
        # （知识卡路径或 PatternDB 模式 ID）。缺省时回退当前 target 的复合 ID，
        # 行为与旧版完全一致。
        "source_knowledge_refs": _parse_source_knowledge_refs(decision.get("source_knowledge_refs")),
        "machine_decision": {
            "schema_version": MACHINE_DECISION_SCHEMA_VERSION,
            "source": str(decision_path),
            "evidence_summary": evidence_summary,
            "evidence_refs": evidence_refs,
            "runner_summary": str(runner_summary_path),
            **({"store_command": store_command} if store_command is not None else {}),
        },
    }
    for key in MACHINE_DECISION_GATE_KEYS:
        info[f"{key}_pass"] = gate_passed[key]
        info[f"{key}_notes"] = gate_notes[key]
    return info, prefill, findings_dir, report_path, report_content


def run_scaffold(args: argparse.Namespace) -> dict[str, Any]:
    """Load the canonical finding and emit the machine-filled decision skeleton."""
    try:
        from tools.decision_scaffold import build_validate_scaffold
    except ImportError:  # pragma: no cover - direct tools/ execution
        from decision_scaffold import build_validate_scaffold  # type: ignore

    if args.findings_dir:
        findings_dir = Path(args.findings_dir).expanduser()
        if not findings_dir.is_absolute():
            findings_dir = (Path.cwd() / findings_dir).resolve()
    elif args.target:
        findings_dir = BASE_DIR / "findings" / target_storage_key(args.target)
    else:
        raise ValidationInputUnavailable("--scaffold requires --target or --findings-dir")
    repo_root = findings_dir.parent.parent
    target = canonical_target_value(args.target or findings_dir.name)
    prefill = load_finding_prefill(
        str(findings_dir), args.finding_id, migrate_legacy=False, include_canonical=True,
        repo_root=repo_root, target=target,
    )
    if not prefill:
        raise ValidationInputUnavailable(
            f"finding id not found in Store: {args.finding_id}"
        )
    canonical = (
        prefill.get("_canonical_finding")
        if isinstance(prefill.get("_canonical_finding"), dict)
        else {}
    )
    finding = canonical or {
        "id": prefill.get("finding_id"),
        "url": prefill.get("endpoint"),
        "endpoint": prefill.get("endpoint"),
        "type": prefill.get("vuln_type"),
    }
    scaffold = build_validate_scaffold(
        repo_root,
        Path(findings_dir),
        finding,
        target=str(prefill.get("target") or ""),
    )
    if prefill.get("store_id"):
        scaffold["store_preconditions"] = {
            "assessment_id": (canonical.get("assessment") or {}).get("id"),
            "delivery_id": next((item["id"] for item in canonical["deliveries"]
                                 if item["destination"] == "internal-review"), None),
        }
    return scaffold


def run_machine_preflight(args: argparse.Namespace) -> dict[str, Any]:
    """Read and validate a machine decision without creating or changing state."""
    errors: list[str] = []

    def capture(callback):
        try:
            return callback()
        except (KeyError, OSError, ValueError) as exc:
            errors.append(str(exc))
            return None

    loaded = capture(lambda: _load_machine_decision(args.decision_json))
    if loaded is None:
        raise MachineDecisionPreflightError(errors)
    decision, decision_path = loaded

    decision_target = capture(lambda: canonical_target_value(_required_text(decision.get("target"), "target")))
    finding_id = capture(lambda: _required_text(decision.get("finding_id"), "finding_id"))
    if finding_id is not None and finding_id != args.finding_id:
        errors.append("decision.finding_id must exactly match --finding-id")

    findings_dir = capture(
        lambda: _resolve_machine_findings_dir(args, decision_target or "")
    )
    repo_root = (
        capture(lambda: _machine_repo_root(findings_dir, explicit_findings_dir=args.findings_dir))
        if findings_dir is not None
        else None
    )
    prefill = None
    if findings_dir is not None and finding_id and repo_root is not None and decision_target is not None:
        prefill = capture(
            lambda: load_finding_prefill(
                str(findings_dir),
                finding_id,
                migrate_legacy=False,
                include_canonical=True,
                repo_root=repo_root,
                target=decision_target,
            )
        )
        if prefill == {}:
            errors.append(f"finding id not found in Store: {finding_id}")

    if prefill:
        if decision_target is not None:
            indexed_target = canonical_target_value(str(prefill.get("target") or ""))
            if indexed_target != decision_target:
                errors.append("decision.target does not match the Store target")

    decision_endpoint = capture(lambda: _required_text(decision.get("endpoint"), "endpoint"))
    if prefill and decision_endpoint is not None and not _machine_endpoints_match(
        decision_endpoint,
        str(prefill.get("endpoint") or ""),
    ):
        errors.append("decision.endpoint does not match the canonical finding endpoint")

    decision_vuln_class = capture(
        lambda: _normalize_vuln_class(_required_text(decision.get("vuln_class"), "vuln_class"))
    )
    if prefill and decision_vuln_class is not None:
        indexed_vuln_class = _normalize_vuln_class(prefill.get("vuln_type"))
        # 经 closure 词汇 owner 归一后比较：prefill 的 type 来自 scanner 词汇
        # （auth_bypass），runner/decision 用 closure 词汇（Authz）——同一概念的
        # 两套拼写不应判为不匹配（lab-r5 实测撞墙根因）。未知类回退裸比较。
        decision_canonical = canonical_vuln_class(decision_vuln_class)
        indexed_canonical = canonical_vuln_class(indexed_vuln_class)
        classes_match = (
            (decision_canonical and indexed_canonical and decision_canonical == indexed_canonical)
            if (decision_canonical and indexed_canonical)
            else (decision_vuln_class == indexed_vuln_class)
        )
        if not decision_vuln_class or not classes_match:
            errors.append("decision.vuln_class does not match the canonical finding class")

    capture(lambda: _parse_machine_gates(decision.get("gates")))
    capture(lambda: _parse_machine_seven_questions(decision.get("seven_question_gate")))
    capture(lambda: _parse_machine_cvss(decision.get("cvss")))
    capture(lambda: _required_text(decision.get("impact"), "impact"))
    if "severity" in decision:
        capture(lambda: _parse_machine_severity(decision["severity"]))
    decision_method = capture(lambda: normalize_http_method(decision.get("method") or "GET"))

    store_command = None
    evidence = decision.get("evidence")
    if not isinstance(evidence, dict):
        errors.append("decision.evidence must be an object")
    else:
        capture(lambda: _required_text(evidence.get("summary"), "evidence.summary"))
        evidence_refs = capture(
            lambda: _resolve_machine_evidence_refs(evidence.get("refs"), repo_root=repo_root or BASE_DIR)
        )
        if (
            evidence_refs is not None
            and decision_target is not None
            and finding_id
            and decision_endpoint is not None
            and decision_method is not None
            and findings_dir is not None
            and prefill
        ):
            witness = capture(
                lambda: _validate_machine_runner_witness(
                    evidence,
                    evidence_refs=evidence_refs,
                    decision_target=decision_target,
                    finding_id=finding_id,
                    decision_endpoint=decision_endpoint,
                    decision_method=decision_method,
                    findings_dir=findings_dir,
                    prefill=prefill,
                    repo_root=repo_root or BASE_DIR,
                )
            )
            if witness is not None and witness[1]:
                store_command = capture(lambda: _primary_validation_command(decision, prefill, witness[1]))

    report_result = capture(
        lambda: _resolve_machine_report(
            decision.get("report"),
            findings_dir=findings_dir or BASE_DIR,
            repo_root=repo_root or BASE_DIR,
        )
    )
    if report_result is not None and findings_dir is not None and finding_id:
        report_path, report_content = report_result
        capture(
            lambda: _assert_machine_report_path_available(
                findings_dir,
                finding_id=finding_id,
                report_path=report_path,
                report_content=report_content,
                repo_root=repo_root or BASE_DIR,
                target=decision_target,
                store_command=store_command,
            )
        )

    if errors:
        raise MachineDecisionPreflightError(errors)
    return {
        "status": "preflight_ok",
        "read_only": True,
        "decision_path": str(decision_path),
        "target": decision_target,
        "finding_id": finding_id,
        "findings_dir": str(findings_dir),
        "report_path": str(report_result[0]),
    }


def run_machine_validation(args: argparse.Namespace) -> dict[str, Any]:
    """Apply an explicit non-TTY validation decision through existing owners only."""
    info, prefill, findings_dir, report_path, report_content = _build_machine_validation_input(args)
    repo_root = _machine_repo_root(findings_dir, explicit_findings_dir=args.findings_dir)
    output_path = ensure_report_output_path(report_path)
    _write_machine_report(output_path, report_content)

    all_pass = all(bool(info.get(f"{key}_pass")) for key in MACHINE_DECISION_GATE_KEYS)
    summary = build_validation_summary(info, all_pass=all_pass, report_path=output_path)
    summary_path = write_validation_summary(summary, output_path, repo_root=repo_root)
    validation_sync = sync_validation_artifacts(summary, repo_root=repo_root)
    if validation_sync.get("status") in {"updated", "deduplicated"} and summary.get("report_ready"):
        command = info["machine_decision"]["store_command"]
        report_id = "report:" + command["assessment_id"].split(":", 1)[1]
        try:
            receipt = runtime_store(repo_root, summary["target"]).register_report(
                command_id=report_id, report_id=report_id, finding_id=summary["finding_id"],
                assessment_id=command["assessment_id"], delivery_id=command["delivery_id"],
                artifact=str(output_path), actor="validate",
            )
            validation_sync["report"] = {"id": report_id, "replayed": receipt["replayed"]}
        except (StoreError, OSError) as exc:
            validation_sync.update(status="partial", reason=f"report registration rejected: {exc}")
    summary["validation_sync"] = validation_sync
    summary_path = write_validation_summary(summary, output_path, repo_root=repo_root)
    retry = _validation_sync_retry_result(
        validation_sync,
        report_path=output_path,
        summary_path=summary_path,
    )
    if retry:
        raise ValidationSyncError(retry)
    update_runtime_state_after_validate(summary, str(findings_dir), repo_root=repo_root)
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
    parser = argparse.ArgumentParser(description="Machine-decision validation backend")
    parser.add_argument("--findings-dir", default="", help="Target-owned findings directory")
    parser.add_argument("--finding-id", default="", help="Prefill target/type/endpoint from the Store finding")
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
    parser.add_argument(
        "--scaffold",
        action="store_true",
        help=(
            "Emit a machine-filled decision JSON skeleton for --finding-id "
            "(mechanical fields pre-filled: endpoint/runner_summary/refs/report "
            "path; judgment fields left empty). Pipe to a file, fill the "
            "judgment fields, then run --preflight."
        ),
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Read-only machine decision validation; aggregate errors without writing state.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine validation result as JSON.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Apply an explicit machine decision; fail closed without --decision-json."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.scaffold:
            if not args.finding_id:
                raise ValidationInputUnavailable("--scaffold requires --finding-id")
            result = run_scaffold(args)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.preflight:
            if not args.decision_json:
                raise MachineDecisionPreflightError(("--preflight requires --decision-json",))
            result = run_machine_preflight(args)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            else:
                print(
                    "machine validation preflight ok "
                    f"finding={result['finding_id']} report={result['report_path']}"
                )
            return 0
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
        raise ValidationInputUnavailable(
            "validation requires --decision-json; no state was written"
        )
    except MachineDecisionPreflightError as exc:
        if args.preflight and args.json:
            print(
                json.dumps(
                    {
                        "status": "preflight_invalid",
                        "read_only": True,
                        "errors": list(exc.errors),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        else:
            print(f"validate preflight: {exc}", file=sys.stderr)
        return 2
    except ValidationInputUnavailable as exc:
        print(f"validate: {exc}", file=sys.stderr)
        return 2
    except ValidationSyncError as exc:
        if args.json:
            print(json.dumps(exc.result, ensure_ascii=False, sort_keys=True))
        else:
            print(f"validate: {exc}", file=sys.stderr)
        return 2
    except (KeyError, OSError, ValueError) as exc:
        print(f"validate: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
