#!/usr/bin/env python3
"""Deterministic A/B evaluator for the web2-vuln-classes Skill.

This script measures loaded-context value, not live model behavior:

- baseline arm: context_pack cards, reference_hints, checks, and seeds
- enhanced arm: baseline plus skills/web2-vuln-classes/SKILL.md

The output shows which evidence-gate / stop-condition / chain-connector
signals already live in compact cards/references and which still depend on the
large default Skill. That gives a safe "measure before slimming" baseline.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
TOOLS_DIR = BASE_DIR / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

try:
    from context_pack import build_context_pack
except ImportError:  # pragma: no cover - direct tools/ execution
    from tools.context_pack import build_context_pack  # type: ignore


DEFAULT_CASES = BASE_DIR / "tests" / "skill-validator" / "cases" / "web2_vuln_classes_ab_cases.json"
WEB2_SKILL = BASE_DIR / "skills" / "web2-vuln-classes" / "SKILL.md"


@dataclass(frozen=True)
class Material:
    text: str
    paths: list[str]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _load_cases(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError(f"invalid cases file: {path}")
    return payload


def _repo_path(repo_root: Path, value: str) -> Path:
    return repo_root / value


def _compact_lines(items: list[Any]) -> str:
    return "\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True) for item in items)


def _build_baseline_material(repo_root: Path, pack: dict) -> Material:
    paths: list[str] = []
    parts: list[str] = []

    for key in ("knowledge_cards",):
        for rel in pack.get(key, []) or []:
            if not isinstance(rel, str):
                continue
            path = _repo_path(repo_root, rel)
            paths.append(rel)
            parts.append(f"\n--- {rel} ---\n{_read_text(path)}")

    for hint in pack.get("reference_hints", []) or []:
        if not isinstance(hint, dict):
            continue
        rel = str(hint.get("path") or "").strip()
        if not rel:
            continue
        path = _repo_path(repo_root, rel)
        paths.append(rel)
        parts.append(f"\n--- {rel} ---\n{_read_text(path)}")

    parts.append("\n--- context_pack.required_checks ---\n" + _compact_lines(pack.get("required_checks", []) or []))
    parts.append("\n--- context_pack.hypothesis_seeds ---\n" + _compact_lines(pack.get("hypothesis_seeds", []) or []))
    return Material(text="\n".join(parts).lower(), paths=paths)


def _contains_all(text: str, terms: list[str]) -> bool:
    return all(str(term).lower() in text for term in terms)


def _score_signals(material: Material, checks: list[dict]) -> tuple[int, list[str], list[str]]:
    score = 0
    passed: list[str] = []
    missing: list[str] = []
    for check in checks:
        check_id = str(check.get("id") or "unnamed")
        terms = [str(item) for item in check.get("terms", []) if str(item).strip()]
        if terms and _contains_all(material.text, terms):
            score += 1
            passed.append(check_id)
        else:
            missing.append(check_id)
    return score, passed, missing


def _line_count(path: Path) -> int:
    return len(_read_text(path).splitlines())


def evaluate_cases(repo_root: Path = BASE_DIR, cases_path: Path = DEFAULT_CASES) -> dict:
    payload = _load_cases(cases_path)
    cases = payload["cases"]
    web2_text = _read_text(repo_root / "skills" / "web2-vuln-classes" / "SKILL.md").lower()
    rows: list[dict] = []

    for case in cases:
        focus = str(case["focus"])
        pack = build_context_pack(repo_root, target="eval.test", focus=focus)
        baseline = _build_baseline_material(repo_root, pack)
        enhanced = Material(
            text=baseline.text + "\n--- skills/web2-vuln-classes/SKILL.md ---\n" + web2_text,
            paths=[*baseline.paths, "skills/web2-vuln-classes/SKILL.md"],
        )

        expected_cards = [str(item) for item in case.get("expected_cards", [])]
        forbidden_cards = [str(item) for item in case.get("forbidden_cards", [])]
        cards = [str(item) for item in pack.get("knowledge_cards", []) or []]
        route_missing = [card for card in expected_cards if card not in cards]
        forbidden_present = [card for card in forbidden_cards if card in cards]
        route_score = sum(card in cards for card in expected_cards)
        forbidden_score = sum(card not in cards for card in forbidden_cards)
        route_max = len(expected_cards) + len(forbidden_cards)

        signal_checks = [item for item in case.get("signal_checks", []) if isinstance(item, dict)]
        baseline_signal, baseline_passed, baseline_missing = _score_signals(baseline, signal_checks)
        enhanced_signal, enhanced_passed, enhanced_missing = _score_signals(enhanced, signal_checks)

        max_score = route_max + len(signal_checks)
        baseline_score = route_score + forbidden_score + baseline_signal
        enhanced_score = route_score + forbidden_score + enhanced_signal
        skill_only = sorted(set(enhanced_passed) - set(baseline_passed))

        rows.append({
            "id": case["id"],
            "lane": case["lane"],
            "selected_skill": pack.get("selected_skill_id"),
            "expected_skill": case.get("expected_skill"),
            "knowledge_cards": cards,
            "reference_hints": pack.get("reference_hints", []) or [],
            "route_missing_expected_cards": route_missing,
            "route_forbidden_cards_present": forbidden_present,
            "baseline_score": baseline_score,
            "enhanced_score": enhanced_score,
            "max_score": max_score,
            "delta": enhanced_score - baseline_score,
            "baseline_signal_passed": baseline_passed,
            "baseline_signal_missing": baseline_missing,
            "enhanced_signal_passed": enhanced_passed,
            "enhanced_signal_missing": enhanced_missing,
            "skill_only_signal_checks": skill_only,
            "baseline_paths": baseline.paths,
        })

    summary = {
        "case_count": len(rows),
        "web2_skill_lines": _line_count(repo_root / "skills" / "web2-vuln-classes" / "SKILL.md"),
        "baseline_total": sum(row["baseline_score"] for row in rows),
        "enhanced_total": sum(row["enhanced_score"] for row in rows),
        "max_total": sum(row["max_score"] for row in rows),
        "delta_total": sum(row["delta"] for row in rows),
        "cases_with_delta": [row["id"] for row in rows if row["delta"] > 0],
        "cases_missing_even_enhanced": [
            row["id"] for row in rows if row["enhanced_signal_missing"]
        ],
        "route_gap_cases": [
            row["id"] for row in rows
            if row["route_missing_expected_cards"] or row["route_forbidden_cards_present"]
        ],
        "reference_hint_paths": sorted({
            str(hint.get("path"))
            for row in rows
            for hint in row["reference_hints"]
            if isinstance(hint, dict) and hint.get("path")
        }),
    }
    return {
        "meta": payload.get("meta", {}),
        "summary": summary,
        "rows": rows,
    }


def format_markdown(result: dict) -> str:
    summary = result["summary"]
    lines = [
        "# Web2 Vuln Classes A/B Evaluation",
        "",
        "## Scope",
        "",
        "Deterministic local A/B for `skills/web2-vuln-classes/SKILL.md`.",
        "This measures loaded-context signal availability, not live model accuracy.",
        "",
        "## Summary",
        "",
        f"- Cases: {summary['case_count']}",
        f"- web2-vuln-classes lines: {summary['web2_skill_lines']}",
        f"- Baseline score: {summary['baseline_total']}/{summary['max_total']}",
        f"- Enhanced score: {summary['enhanced_total']}/{summary['max_total']}",
        f"- Delta: +{summary['delta_total']}",
        f"- Cases with Skill-only signal: {', '.join(summary['cases_with_delta']) or 'none'}",
        f"- Cases still missing enhanced signals: {', '.join(summary['cases_missing_even_enhanced']) or 'none'}",
        f"- Route/card gap cases: {', '.join(summary['route_gap_cases']) or 'none'}",
        "",
        "Reference hints observed:",
        "",
    ]
    if summary["reference_hint_paths"]:
        lines.extend(f"- `{path}`" for path in summary["reference_hint_paths"])
    else:
        lines.append("- none")

    lines.extend([
        "",
        "## Per-case results",
        "",
        "| Case | Lane | Selected Skill | Baseline | Enhanced | Delta | Skill-only checks | Route/card gap | Enhanced missing |",
        "|---|---|---|---:|---:|---:|---|---|---|",
    ])
    for row in result["rows"]:
        route_gap = []
        if row["route_missing_expected_cards"]:
            route_gap.append("missing: " + ", ".join(row["route_missing_expected_cards"]))
        if row["route_forbidden_cards_present"]:
            route_gap.append("present: " + ", ".join(row["route_forbidden_cards_present"]))
        lines.append(
            "| {id} | {lane} | {skill} | {base}/{max_score} | {enh}/{max_score} | +{delta} | {only} | {route_gap} | {missing} |".format(
                id=row["id"],
                lane=row["lane"],
                skill=row["selected_skill"],
                base=row["baseline_score"],
                enh=row["enhanced_score"],
                max_score=row["max_score"],
                delta=row["delta"],
                only=", ".join(row["skill_only_signal_checks"]) or "-",
                route_gap="; ".join(route_gap) or "-",
                missing=", ".join(row["enhanced_signal_missing"]) or "-",
            )
        )

    lines.extend([
        "",
        "## Interpretation",
        "",
        "- If baseline and enhanced both pass a signal, that signal already lives in compact cards/references.",
        "- If only enhanced passes, the compact Skill still carries a decision-layer signal that has not been duplicated into references.",
        "- If enhanced misses a signal or a route/card gap appears, fix cards/seeds/routes before claiming the slim is safe.",
        "- A future live LLM A/B can reuse the same case file; this report is the deterministic post-slim regression baseline.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate web2-vuln-classes loaded-context A/B.")
    parser.add_argument("--repo-root", default=str(BASE_DIR))
    parser.add_argument("--cases", default=str(DEFAULT_CASES))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--report", default="", help="Write Markdown report to this path.")
    args = parser.parse_args(argv)

    result = evaluate_cases(Path(args.repo_root), Path(args.cases))
    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(format_markdown(result) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(format_markdown(result))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
