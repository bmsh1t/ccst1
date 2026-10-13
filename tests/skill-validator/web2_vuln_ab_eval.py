#!/usr/bin/env python3
"""Current-source offline signal diagnostic using historical Web2 scoring.

This script measures material availability, not live model behavior:

- baseline: context_pack required-check references
- enhanced: baseline plus expected card bodies and the current Web2 method

Historical cases, score rules and maxima are retained. This diagnostic does
not rerun or replace the recorded Skill experiments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import shutil
from tempfile import TemporaryDirectory
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


from tools.target_store import TargetStore


DEFAULT_CASES = BASE_DIR / "tests" / "skill-validator" / "cases" / "web2_vuln_classes_ab_cases.json"
WEB2_METHOD = "knowledge/playbooks/web2-evidence-contracts.md"


@dataclass(frozen=True)
class Material:
    text: str
    paths: list[str]


def _load_cases(path: Path) -> tuple[dict, str]:
    content = path.read_bytes()
    payload = json.loads(content)
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError(f"invalid cases file: {path}")
    return payload, hashlib.sha256(content).hexdigest()


def _repo_path(repo_root: Path, value: str) -> Path:
    return repo_root / value


def _compact_lines(items: list[Any]) -> str:
    return "\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True) for item in items)


def _build_baseline_material(repo_root: Path, pack: dict) -> Material:
    """Baseline arm: required checks only.

    Static seeds are retired (2026-09-13 native audit): the baseline arm no
    longer includes a seeds transcript. Card bodies are AI-pulled on demand,
    not pre-loaded, so they belong to neither arm by default.
    """
    paths: list[str] = []
    parts: list[str] = ["\n--- context_pack.required_checks ---\n" + _compact_lines(pack.get("required_checks", []) or [])]
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


def evaluate_cases(repo_root: Path = BASE_DIR, cases_path: Path = DEFAULT_CASES) -> dict:
    payload, cases_sha256 = _load_cases(cases_path)
    cases = payload["cases"]
    method_bytes = (repo_root / WEB2_METHOD).read_bytes()
    method_text = method_bytes.decode("utf-8")
    if not method_text.strip():
        raise ValueError(f"empty Web2 method: {WEB2_METHOD}")
    rows: list[dict] = []

    with TemporaryDirectory(prefix="ccst-skill-eval-") as directory:
        fixture = Path(directory)
        shutil.copytree(repo_root / "knowledge", fixture / "knowledge")
        TargetStore(fixture, "eval.test").initialize()
        for case in cases:
            focus = str(case["focus"])
            pack = build_context_pack(fixture, target="eval.test", focus=focus)
            baseline = _build_baseline_material(repo_root, pack)
            # The diagnostic loads the case's named cards and current method;
            # catalog visibility does not establish actual model selection.
            enhanced_parts = [baseline.text]
            enhanced_paths = [*baseline.paths]
            for rel in case.get("expected_cards", []) or []:
                rel = str(rel)
                path = _repo_path(repo_root, rel)
                enhanced_parts.append(f"\n--- {rel} ---\n{path.read_text(encoding='utf-8')}")
                enhanced_paths.append(rel)
            enhanced_parts.append(f"\n--- {WEB2_METHOD} ---\n{method_text}")
            enhanced_paths.append(WEB2_METHOD)
            enhanced = Material(
                text="\n".join(enhanced_parts).lower(),
                paths=enhanced_paths,
            )

            expected_cards = [str(item) for item in case.get("expected_cards", [])]
            forbidden_cards = [str(item) for item in case.get("forbidden_cards", [])]
            # Keyword selection retired (2026-09-13 native audit): the card
            # catalog is the AI-visible discovery surface. The eval checks
            # discoverability; auto-selection no longer exists, so forbidden-card
            # noise checks are vacuously satisfied and kept only for schema.
            visible_cards = {
                str(item.get("file") or "")
                for item in pack.get("card_catalog", []) or []
                if isinstance(item, dict)
            }
            cards = sorted(visible_cards)
            route_missing = [card for card in expected_cards if card not in visible_cards]
            selected_cards: set[str] = set()
            forbidden_present: list[str] = []
            route_score = sum(card in cards for card in expected_cards)
            forbidden_score = sum(card not in selected_cards for card in forbidden_cards)
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
                "enhanced_paths": enhanced.paths,
            })

    summary = {
        "case_count": len(rows),
        "method_path": WEB2_METHOD,
        "method_lines": len(method_text.splitlines()),
        "method_sha256": hashlib.sha256(method_bytes).hexdigest(),
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
        "diagnostic": {
            "kind": "current-source-offline-signals",
            "cases_sha256": cases_sha256,
            "historical_fields": "meta/expected_skill retain historical labels; skill_only_signal_checks means enhanced-only signals.",
        },
        "summary": summary,
        "rows": rows,
    }


def format_markdown(result: dict) -> str:
    summary = result["summary"]
    lines = [
        "# Web2 Current-source Offline Signal Diagnostic",
        "",
        "## Scope",
        "",
        f"Current-source offline signal diagnostic for `{summary['method_path']}`.",
        "This measures loaded-context signal availability, not live model accuracy.",
        "Historical cases and scoring rules are retained; this does not rerun the historical Skill A/B.",
        "The legacy skill_only_signal_checks field means enhanced-only signals.",
        "",
        "## Summary",
        "",
        f"- Cases: {summary['case_count']}",
        f"- Method lines: {summary['method_lines']}",
        f"- Method SHA-256: {summary['method_sha256']}",
        f"- Baseline score: {summary['baseline_total']}/{summary['max_total']}",
        f"- Enhanced score: {summary['enhanced_total']}/{summary['max_total']}",
        f"- Delta: +{summary['delta_total']}",
        f"- Cases with enhanced-only signal: {', '.join(summary['cases_with_delta']) or 'none'}",
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
        "| Case | Lane | Baseline | Enhanced | Delta | Enhanced-only checks | Route/card gap | Enhanced missing |",
        "|---|---|---:|---:|---:|---|---|---|",
    ])
    for row in result["rows"]:
        route_gap = []
        if row["route_missing_expected_cards"]:
            route_gap.append("missing: " + ", ".join(row["route_missing_expected_cards"]))
        if row["route_forbidden_cards_present"]:
            route_gap.append("present: " + ", ".join(row["route_forbidden_cards_present"]))
        lines.append(
            "| {id} | {lane} | {base}/{max_score} | {enh}/{max_score} | +{delta} | {only} | {route_gap} | {missing} |".format(
                id=row["id"],
                lane=row["lane"],
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
        "- Baseline scores required-check references only; enhanced also loads the named cards and current method.",
        "- Enhanced-only signals identify material available in that combined context, without attributing it to one document.",
        "- A missing enhanced signal or catalog gap is an engineering regression to investigate.",
        "- Catalog visibility and lexical scores do not prove model discovery, selection, or reasoning quality.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diagnose current Web2 material with historical offline signal scoring.")
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
