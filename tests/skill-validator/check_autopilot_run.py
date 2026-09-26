#!/usr/bin/env python3
"""Validate one /autopilot pressure-test run from on-disk artifacts.

The validator is intentionally structural: it does not judge whether a finding
is exploitable. It only checks that a completed run left the evidence needed to
review the automation loop objectively.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
TOOLS_DIR = BASE_DIR / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

try:
    from action_queue import DEFAULT_STOP_CONDITION, FINAL_STATUSES, load_queue
    from target_store import runtime_store, StoreError
    from target_paths import canonical_target_value, target_storage_key
except ImportError:  # pragma: no cover - direct execution fallback
    from tools.action_queue import DEFAULT_STOP_CONDITION, FINAL_STATUSES, load_queue  # type: ignore
    from tools.target_store import runtime_store, StoreError  # type: ignore
    from tools.target_paths import canonical_target_value, target_storage_key  # type: ignore


CONTEXT_ARTIFACT_NAMES = {
    "session.json",
    "checkpoint.json",
    "checkpoint_latest.json",
    "last_checkpoint.json",
    "autopilot_run.json",
    "run.json",
}
CONTEXT_ARTIFACT_PATTERNS = ("*checkpoint*.json", "*autopilot*.json", "*.log", "*.md", "*.txt")
COMMAND_HINT_FIELDS = ("command_hint", "recommended_executable_action", "action")
EXECUTABLE_RE = re.compile(
    r"(^|\s)(python3?|node|npm|npx|bash|sh|curl|smart-search|ffuf|nuclei|semgrep)\b"
    r"|tools/[A-Za-z0-9_./-]+\.py\b"
    r"|python3?\s+tools/",
    re.IGNORECASE,
)
HIGH_RISK_RE = re.compile(
    r"\b("
    r"rce|remote code execution|ssrf|cache|web-cache|smuggling|request smuggling|"
    r"race|upload execution|deserialization|command injection|ssti|xxe"
    r")\b",
    re.IGNORECASE,
)

CHECK_WEIGHTS = {
    "context_pack": 30,
    "executable_action": 25,
    "evidence_path": 25,
    "queue_resolution_and_stop": 20,
}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_text(path: Path, limit: int = 200_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _find_nonempty_key(value: Any, keys: set[str]) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in keys:
                if isinstance(item, (list, dict)) and item:
                    return item
                if isinstance(item, str) and item.strip():
                    return item
                if isinstance(item, bool):
                    return item
            found = _find_nonempty_key(item, keys)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_nonempty_key(item, keys)
            if found:
                return found
    return None


def _compact(value: Any, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _discover_context_artifacts(repo_root: Path, target_key: str) -> list[tuple[Path, Any, str]]:
    state_dir = repo_root / "state" / target_key
    if not state_dir.is_dir():
        return []

    candidates: dict[Path, None] = {}
    for name in CONTEXT_ARTIFACT_NAMES:
        path = state_dir / name
        if path.is_file():
            candidates[path] = None
    for pattern in CONTEXT_ARTIFACT_PATTERNS:
        for path in state_dir.glob(pattern):
            if path.is_file() and path.name != "action_queue.json":
                candidates[path] = None

    artifacts: list[tuple[Path, Any, str]] = []
    for path in sorted(candidates):
        text = _read_text(path)
        data = _read_json(path) if path.suffix == ".json" else None
        artifacts.append((path, data, text))
    return artifacts


def _check_context_pack(repo_root: Path, target_key: str) -> dict:
    artifacts = _discover_context_artifacts(repo_root, target_key)
    context_pack_used = False
    route_detail = None
    evidence: list[str] = []

    for path, data, text in artifacts:
        label = str(path.relative_to(repo_root))
        if isinstance(data, (dict, list)):
            if _find_nonempty_key(data, {"context_pack"}):
                context_pack_used = True
                evidence.append(f"{label}: context_pack")
            detail = _find_nonempty_key(data, {"knowledge_cards", "reference_hints"})
            if detail:
                route_detail = detail
                evidence.append(f"{label}: route_detail={_compact(detail)}")

        lowered = text.lower()
        if "tools/context_pack.py" in lowered or "context_pack.py" in lowered:
            context_pack_used = True
            evidence.append(f"{label}: context_pack command")
        if not route_detail and ("reference_hints" in text or "knowledge_cards" in text):
            route_detail = "text-marker"
            evidence.append(f"{label}: route detail marker")

    passed = bool(context_pack_used and route_detail)
    missing = []
    if not context_pack_used:
        missing.append("context_pack_used")
    if not route_detail:
        missing.append("knowledge_cards_or_reference_hints")
    return {
        "passed": passed,
        "evidence": "; ".join(evidence[:6]) if evidence else "no context-pack artifact found",
        "missing": missing,
    }


def _action_command_text(action: dict) -> str:
    parts = []
    for field in COMMAND_HINT_FIELDS:
        value = action.get(field)
        if isinstance(value, dict):
            parts.extend(str(item) for item in value.values())
        elif isinstance(value, list):
            parts.extend(str(item) for item in value)
        else:
            parts.append(str(value or ""))
    return " ".join(parts)


def _check_executable_action(queue: dict) -> dict:
    actions = [item for item in queue.get("actions", []) if isinstance(item, dict)]
    for item in actions:
        text = _action_command_text(item)
        if EXECUTABLE_RE.search(text):
            return {
                "passed": True,
                "evidence": f"{item.get('id', '<no-id>')}: {_compact(text)}",
                "missing": [],
            }
    return {
        "passed": False,
        "evidence": "no action_queue item contains an executable command/script hint",
        "missing": ["script_or_command_action"],
    }


def _check_evidence_path(store) -> dict:
    """Require registered, currently intact raw material; paths alone prove nothing."""
    page = store.page("operations", limit=1000)
    verified = []
    invalid = []
    while True:
        for operation in page["items"]:
            try:
                evidence = store.verify_operation(operation["id"])
            except (OSError, ValueError) as exc:
                invalid.append(f"{operation['id']}: {exc}")
            else:
                if evidence["artifact_count"]:
                    verified.append(operation["id"])
        if not page["has_more"]:
            break
        page = store.page("operations", limit=1000, cursor=page["next_cursor"])
    passed = bool(verified) and not invalid
    return {
        "passed": passed,
        "evidence": "; ".join(invalid[:3] or verified[:3]) or "no registered raw observation",
        "missing": [] if passed else ["registered_intact_raw_evidence"],
    }


def _is_high_risk_action(action: dict) -> bool:
    metadata = action.get("metadata") if isinstance(action.get("metadata"), dict) else {}
    text = " ".join(
        str(value or "")
        for value in (
            action.get("type"),
            action.get("evidence_type"),
            action.get("evidence"),
            action.get("next_question"),
            action.get("action"),
            action.get("command_hint"),
            metadata.get("vuln_class"),
            metadata.get("family"),
            metadata.get("lane"),
        )
    )
    return bool(HIGH_RISK_RE.search(text))


def _has_custom_stop_condition(action: dict) -> bool:
    value = str(action.get("stop_condition") or "").strip()
    return bool(value and value != DEFAULT_STOP_CONDITION)


def _check_queue_resolution_and_stop(queue: dict) -> dict:
    actions = [item for item in queue.get("actions", []) if isinstance(item, dict)]
    final_items = [
        item for item in actions
        if str(item.get("status") or "").strip().lower() in FINAL_STATUSES
    ]
    high_risk_items = [item for item in actions if _is_high_risk_action(item)]
    missing_stop = [
        str(item.get("id") or "<no-id>")
        for item in high_risk_items
        if not _has_custom_stop_condition(item)
    ]

    passed = bool(final_items) and not missing_stop
    evidence_parts = []
    if final_items:
        evidence_parts.append(
            "final_status="
            + ", ".join(
                f"{item.get('id', '<no-id>')}:{item.get('status')}"
                for item in final_items[:3]
            )
        )
    if high_risk_items and not missing_stop:
        evidence_parts.append(
            "high_risk_stop="
            + ", ".join(str(item.get("id") or "<no-id>") for item in high_risk_items[:3])
        )
    elif not high_risk_items:
        evidence_parts.append("high_risk_stop=n/a")

    missing = []
    if not final_items:
        missing.append("final_status")
    if missing_stop:
        missing.append("custom_stop_condition_for_high_risk")
    return {
        "passed": passed,
        "evidence": "; ".join(evidence_parts) if evidence_parts else "no action_queue items found",
        "missing": missing,
    }


def _score_context_pack(check: dict) -> int:
    """Context routing has two independently useful breadcrumbs."""
    missing = set(check.get("missing") or [])
    score = 30
    if "context_pack_used" in missing:
        score -= 15
    if "knowledge_cards_or_reference_hints" in missing:
        score -= 15
    return max(score, 0)


def _score_queue_resolution(check: dict) -> int:
    """Queue quality has two halves: resolved item and high-risk stop condition."""
    missing = set(check.get("missing") or [])
    score = 20
    if "final_status" in missing:
        score -= 10
    if "custom_stop_condition_for_high_risk" in missing:
        score -= 10
    return max(score, 0)


def _score_checks(checks: dict[str, dict]) -> tuple[int, int]:
    """Convert structural checks into a deterministic quality score."""
    total = sum(CHECK_WEIGHTS.values())
    score = 0
    for name, check in checks.items():
        max_score = CHECK_WEIGHTS.get(name, 0)
        if name == "context_pack":
            item_score = _score_context_pack(check)
        elif name == "queue_resolution_and_stop":
            item_score = _score_queue_resolution(check)
        else:
            item_score = max_score if check.get("passed") else 0
        check["score"] = item_score
        check["max_score"] = max_score
        score += item_score
    return score, total


def _grade_run(score: int, passed: bool) -> str:
    """Name the run quality without masking hard-contract failures."""
    if passed and score >= 90:
        return "pass"
    if score >= 70:
        return "needs_review"
    return "fail"


def check_run(repo_root: Path | str, target: str) -> dict:
    repo = Path(repo_root).resolve()
    resolved_target = canonical_target_value(target)
    target_key = target_storage_key(resolved_target)
    store = runtime_store(repo, resolved_target)
    binding = store.binding()
    queue = load_queue(repo, resolved_target)
    queue_resolution = _check_queue_resolution_and_stop(queue)
    checks = {
        "context_pack": _check_context_pack(repo, target_key),
        "executable_action": _check_executable_action(queue),
        "evidence_path": _check_evidence_path(store),
        "queue_resolution_and_stop": queue_resolution,
    }
    if store.binding() != binding:
        raise StoreError("target changed during run inspection; retry the read")
    score, max_score = _score_checks(checks)
    passed = all(item["passed"] for item in checks.values())
    return {
        "target": resolved_target,
        "target_key": target_key,
        "passed": passed,
        "score": score,
        "max_score": max_score,
        "grade": _grade_run(score, passed),
        "checks": checks,
    }


def format_report(result: dict) -> str:
    lines = [
        "AUTOPILOT RUN CONTRACT",
        f"target: {result.get('target', '')}",
        f"target_key: {result.get('target_key', '')}",
    ]
    lines.append(f"score: {result.get('score', 0)}/{result.get('max_score', 100)}")
    lines.append(f"grade: {result.get('grade', 'fail')}")
    for name, check in result.get("checks", {}).items():
        status = "PASS" if check.get("passed") else "FAIL"
        score = f"{check.get('score', 0)}/{check.get('max_score', 0)}"
        lines.append(f"[{status}] {name} ({score}): {check.get('evidence', '')}")
        missing = check.get("missing") or []
        if missing:
            lines.append(f"       missing: {', '.join(missing)}")
    lines.append(f"RESULT: {'PASS' if result.get('passed') else 'FAIL'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check whether one /autopilot run left objective runtime artifacts."
    )
    parser.add_argument("--target", required=True, help="Target value used by /autopilot.")
    parser.add_argument("--repo-root", default=str(BASE_DIR), help="Repository root to inspect.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a text report.")
    args = parser.parse_args(argv)

    try:
        result = check_run(Path(args.repo_root), args.target)
    except (OSError, ValueError) as exc:
        print(f"run inspection failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(format_report(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
