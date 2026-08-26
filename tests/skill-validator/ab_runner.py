#!/usr/bin/env python3
"""Small offline A/B row and summary helpers for Skill evaluations.

This module is deliberately only the data boundary around the existing
``web2_vuln_ab_eval.py`` scorer.  It does not invoke a model.  A row records
one case in one arm; callers provide the oracle label when the case file does
not carry one.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_CASES = (
    BASE_DIR / "tests" / "skill-validator" / "cases" / "web2_vuln_classes_ab_cases.json"
)
CONDITIONS = frozenset({"skills_off", "skills_on"})
REQUIRED_FIELDS = (
    "case_id",
    "condition",
    "rep",
    "verdict",
    "oracle_status",
    "turns",
    "tokens",
    "cost_usd",
    "duration_ms",
)
METRIC_FIELDS = ("turns", "tokens", "cost_usd", "duration_ms")

_METRIC_ALIASES = {
    "turns": ("turn",),
    "tokens": ("token_count",),
    "cost_usd": ("cost",),
    "duration_ms": ("duration",),
}

_ORACLE_STATUSES = frozenset({"passed", "failed", "invalid", "unknown", "unavailable"})
_POSITIVE_VERDICTS = frozenset(
    {
        "1",
        "found",
        "hit",
        "positive",
        "present",
        "report",
        "reportable",
        "true",
        "unsafe",
        "vulnerable",
        "yes",
    }
)
_NEGATIVE_VERDICTS = frozenset(
    {
        "0",
        "absent",
        "clean",
        "do-not-report",
        "do_not_report",
        "false",
        "negative",
        "no",
        "not-vulnerable",
        "not_vulnerable",
        "none",
        "safe",
    }
)
_VALID_ORACLE_STATUSES = frozenset({"passed"})


def _canonical_oracle_status(value: Any) -> Any:
    if isinstance(value, Mapping):
        value = _first(value, "status", "state")
    if not isinstance(value, str):
        return value
    status = value.strip().lower().replace("-", "_")
    return {
        "valid": "passed",
        "pass": "passed",
        "ok": "passed",
        "fail": "failed",
    }.get(status, status)


def _first(row: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in row:
            return row[name]
    return None


def _canonical_input(row: Mapping[str, Any]) -> dict[str, Any]:
    """Copy the few historical aliases without changing the output schema."""

    raw = dict(row)
    canonical: dict[str, Any] = {
        "case_id": _first(raw, "case_id", "case", "id"),
        "condition": raw.get("condition"),
        "rep": _first(raw, "rep", "replicate", "iteration"),
        "verdict": raw.get("verdict"),
        "oracle_status": _canonical_oracle_status(
            _first(raw, "oracle_status", "oracle")
        ),
        "turns": _first(raw, "turns", "turn"),
        "tokens": _first(raw, "tokens", "token_count"),
        "cost_usd": _first(raw, "cost_usd", "cost"),
        "duration_ms": _first(raw, "duration_ms", "duration"),
    }

    oracle = _first(raw, "oracle_status", "oracle")
    if isinstance(oracle, Mapping):
        canonical["oracle_label"] = _first(
            oracle, "label", "expected", "truth", "verdict"
        )
    else:
        canonical["oracle_label"] = _first(raw, "oracle_label", "expected", "truth")
    if "oracle_label" not in canonical:
        canonical["oracle_label"] = None
    return canonical


def validate_row(row: Mapping[str, Any] | Any) -> list[str]:
    """Return schema errors for one JSONL row; an empty list means valid.

    Metric fields are required even for offline rows, where each value should
    be ``None`` (or an explicit zero).  This prevents a missing measurement
    from silently looking like a cheap baseline run.
    """

    if not isinstance(row, Mapping):
        return ["row must be a JSON object"]
    value = _canonical_input(row)
    errors: list[str] = []
    for field in REQUIRED_FIELDS:
        if value[field] is None and field not in METRIC_FIELDS:
            errors.append(f"missing field: {field}")
        elif (
            field in METRIC_FIELDS
            and field not in row
            and not any(alias in row for alias in _METRIC_ALIASES[field])
        ):
            errors.append(f"missing field: {field}")

    case_id = value["case_id"]
    if case_id is not None and (not isinstance(case_id, str) or not case_id.strip()):
        errors.append("case_id must be a non-empty string")

    rep = value["rep"]
    if isinstance(rep, bool) or not isinstance(rep, int) or rep < 1:
        errors.append("rep must be a positive integer")

    condition = value["condition"]
    if condition is not None and condition not in CONDITIONS:
        errors.append(f"unknown condition: {condition!r}")

    for field in ("verdict", "oracle_status"):
        item = value[field]
        if item is not None and (not isinstance(item, str) or not item.strip()):
            errors.append(f"{field} must be a non-empty string")

    status = (
        str(value["oracle_status"]).strip().lower()
        if value["oracle_status"] is not None
        else ""
    )
    if status and status not in _ORACLE_STATUSES:
        errors.append(f"unknown oracle_status: {value['oracle_status']!r}")

    label = value["oracle_label"]
    if label is not None and (not isinstance(label, str) or not label.strip()):
        errors.append("oracle_label must be a non-empty string when provided")

    for field in METRIC_FIELDS:
        item = value[field]
        if item is None:
            continue
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            errors.append(f"{field} must be a non-negative number or null")
        elif not math.isfinite(float(item)) or item < 0:
            errors.append(f"{field} must be a non-negative number or null")
        elif field in {"turns", "tokens"} and int(item) != item:
            errors.append(f"{field} must be an integer or null")
    return errors


def normalize_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return the narrow, canonical row representation."""

    errors = validate_row(row)
    if errors:
        raise ValueError("; ".join(errors))
    value = _canonical_input(row)
    normalized = {field: value[field] for field in REQUIRED_FIELDS}
    if value["oracle_label"] is not None:
        normalized["oracle_label"] = value["oracle_label"].strip()
    return normalized


def is_valid_row(row: Mapping[str, Any] | Any) -> bool:
    return not validate_row(row)


def offline_row(
    case_id: str,
    condition: str,
    verdict: str,
    *,
    rep: int = 1,
    oracle_status: str = "passed",
    oracle_label: str | None = None,
    turns: int | None = None,
    tokens: int | None = None,
    cost_usd: float | None = None,
    duration_ms: float | None = None,
) -> dict[str, Any]:
    """Build a row for deterministic fixtures without inventing live metrics."""

    row: dict[str, Any] = {
        "case_id": case_id,
        "condition": condition,
        "rep": rep,
        "verdict": verdict,
        "oracle_status": oracle_status,
        "turns": turns,
        "tokens": tokens,
        "cost_usd": cost_usd,
        "duration_ms": duration_ms,
    }
    if oracle_label is not None:
        row["oracle_label"] = oracle_label
    return normalize_row(row)


def _truth_label(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    label = value.strip().lower().replace(" ", "_")
    if label in _POSITIVE_VERDICTS:
        return True
    if label in _NEGATIVE_VERDICTS:
        return False
    return None


def _case_truth(
    case_id: str, row: Mapping[str, Any], case_truths: Mapping[str, Any]
) -> bool | None:
    label = row.get("oracle_label")
    if label is None:
        label = case_truths.get(case_id)
    if isinstance(label, Mapping):
        label = _first(label, "label", "truth", "expected", "verdict")
    return _truth_label(label)


def _prediction(verdict: Any) -> bool | None:
    return _truth_label(verdict)


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _condition_stats(rows: list[tuple[dict[str, Any], bool, bool]]) -> dict[str, Any]:
    tp = sum(pred and truth for _, truth, pred in rows)
    fp = sum(pred and not truth for _, truth, pred in rows)
    tn = sum(not pred and not truth for _, truth, pred in rows)
    fn = sum(not pred and truth for _, truth, pred in rows)
    return {
        "case_count": len(rows),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "tpr": _rate(tp, tp + fn),
        "fpr": _rate(fp, fp + tn),
        "accuracy": _rate(tp + tn, len(rows)),
    }


def _metric_stats(
    rows: list[tuple[dict[str, Any], bool, bool]],
) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for field in METRIC_FIELDS:
        values = [float(row[field]) for row, _, _ in rows if row[field] is not None]
        output[field] = {
            "observed": len(values),
            "mean": sum(values) / len(values) if values else None,
        }
    return output


def _paired_metric_stats(paired: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for field in METRIC_FIELDS:
        values = [
            float(item["metric_delta"][field])
            for item in paired
            if item["metric_delta"][field] is not None
        ]
        output[field] = {
            "observed": len(values),
            "mean_delta": sum(values) / len(values) if values else None,
        }
    return output


def summarize_rows(
    rows: Iterable[Mapping[str, Any] | Any],
    *,
    case_truths: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize valid paired rows without treating bad rows as baseline.

    ``case_truths`` is useful when reusing existing case files whose scoring
    metadata has no binary vulnerability label.  A row may instead carry an
    ``oracle_label``. Rows with an unknown condition, missing field, unusable
    oracle, or duplicate case/condition/rep are reported as invalid and
    excluded. A paired delta only uses the same ``case_id`` and ``rep`` in
    both conditions.
    """

    truths = case_truths or {}
    raw_rows = list(rows)
    normalized: list[tuple[int, dict[str, Any]]] = []
    invalid: list[dict[str, Any]] = []
    for index, row in enumerate(raw_rows, start=1):
        errors = validate_row(row)
        if errors:
            invalid.append({"row": index, "errors": errors})
            continue
        canonical = normalize_row(row)
        normalized.append((index, canonical))

    grouped: dict[tuple[str, int, str], list[tuple[int, dict[str, Any]]]] = defaultdict(
        list
    )
    for index, row in normalized:
        grouped[(row["case_id"], row["rep"], row["condition"])].append((index, row))

    usable: list[tuple[int, dict[str, Any], bool, bool]] = []
    for _, group in grouped.items():
        if len(group) != 1:
            for index, _ in group:
                invalid.append(
                    {"row": index, "errors": ["duplicate case/condition/rep"]}
                )
            continue
        index, row = group[0]
        status = str(row["oracle_status"]).strip().lower()
        truth = _case_truth(row["case_id"], row, truths)
        prediction = _prediction(row["verdict"])
        row_errors: list[str] = []
        if status not in _VALID_ORACLE_STATUSES:
            row_errors.append("oracle is not usable")
        if truth is None:
            row_errors.append("oracle truth is missing or not binary")
        if prediction is None:
            row_errors.append("verdict is not binary")
        if row_errors:
            invalid.append({"row": index, "errors": row_errors})
            continue
        usable.append((index, row, truth, prediction))

    by_case: dict[
        tuple[str, int], dict[str, tuple[int, dict[str, Any], bool, bool]]
    ] = defaultdict(dict)
    for index, row, truth, prediction in usable:
        by_case[(row["case_id"], row["rep"])][row["condition"]] = (
            index,
            row,
            truth,
            prediction,
        )

    rejected_indexes: set[int] = set()
    for pair in by_case.values():
        if set(pair) != set(CONDITIONS):
            continue
        off_truth = pair["skills_off"][2]
        on_truth = pair["skills_on"][2]
        if off_truth == on_truth:
            continue
        for index, _, _, _ in pair.values():
            rejected_indexes.add(index)
            invalid.append(
                {
                    "row": index,
                    "errors": ["paired oracle truth mismatch"],
                }
            )

    scored = [item for item in usable if item[0] not in rejected_indexes]
    by_condition: dict[str, list[tuple[dict[str, Any], bool, bool]]] = {
        condition: [] for condition in sorted(CONDITIONS)
    }
    for _, row, truth, prediction in scored:
        by_condition[row["condition"]].append((row, truth, prediction))
    condition_stats = {
        condition: _condition_stats(items) for condition, items in by_condition.items()
    }
    metric_stats = {
        condition: _metric_stats(items) for condition, items in by_condition.items()
    }

    paired: list[dict[str, Any]] = []
    unpaired: list[dict[str, Any]] = []
    for case_key in sorted(by_case):
        case_id, rep = case_key
        pair = by_case[case_key]
        if any(index in rejected_indexes for index, _, _, _ in pair.values()):
            continue
        if set(pair) != set(CONDITIONS):
            unpaired.append(
                {"case_id": case_id, "rep": rep, "conditions": sorted(pair)}
            )
            continue
        _, off_row, off_truth, off_prediction = pair["skills_off"]
        _, on_row, on_truth, on_prediction = pair["skills_on"]
        off_correct = off_prediction == off_truth
        on_correct = on_prediction == on_truth
        paired.append(
            {
                "case_id": case_id,
                "rep": rep,
                "truth": off_truth,
                "skills_off_correct": off_correct,
                "skills_on_correct": on_correct,
                "delta": int(on_correct) - int(off_correct),
                "metric_delta": {
                    field: (
                        float(on_row[field]) - float(off_row[field])
                        if on_row[field] is not None and off_row[field] is not None
                        else None
                    )
                    for field in METRIC_FIELDS
                },
            }
        )

    positive_pairs = [item for item in paired if item["truth"]]
    negative_pairs = [item for item in paired if not item["truth"]]
    paired_delta = {
        "case_count": len(paired),
        "improved": [item["case_id"] for item in paired if item["delta"] > 0],
        "regressed": [item["case_id"] for item in paired if item["delta"] < 0],
        "unchanged": [item["case_id"] for item in paired if item["delta"] == 0],
        "accuracy": _rate(sum(item["delta"] for item in paired), len(paired)),
        "tpr": _rate(
            sum(
                int(item["skills_on_correct"]) - int(item["skills_off_correct"])
                for item in positive_pairs
            ),
            len(positive_pairs),
        ),
        "fpr": _rate(
            sum(
                int(not item["skills_on_correct"]) - int(not item["skills_off_correct"])
                for item in negative_pairs
            ),
            len(negative_pairs),
        ),
        "cases": paired,
    }

    return {
        "row_count": len(raw_rows),
        "valid_row_count": len(scored),
        "invalid_row_count": len(invalid),
        "invalid_rows": invalid,
        "conditions": condition_stats,
        "metrics": metric_stats,
        "tpr": {
            condition: stats["tpr"] for condition, stats in condition_stats.items()
        },
        "fpr": {
            condition: stats["fpr"] for condition, stats in condition_stats.items()
        },
        "unpaired_pair_count": len(unpaired),
        "unpaired_pairs": unpaired,
        "paired_metrics": _paired_metric_stats(paired),
        "paired_delta": paired_delta,
    }


def summarize(
    rows: Iterable[Mapping[str, Any] | Any],
    *,
    case_truths: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Short alias used by the command-line and fixture callers."""

    return summarize_rows(rows, case_truths=case_truths)


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """Read JSON objects, preserving malformed lines as invalid row objects."""

    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            rows.append({"_jsonl_error": f"line {line_number}: {exc.msg}"})
            continue
        rows.append(
            value
            if isinstance(value, dict)
            else {"_jsonl_error": f"line {line_number}: row is not an object"}
        )
    return rows


def write_jsonl(path: str | Path, rows: Iterable[Mapping[str, Any]]) -> None:
    """Write canonical rows and fail rather than silently emitting invalid data."""

    encoded = [normalize_row(row) for row in rows]
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in encoded
        ),
        encoding="utf-8",
    )


def load_existing_evaluation(
    repo_root: str | Path = BASE_DIR,
    cases_path: str | Path = DEFAULT_CASES,
) -> dict[str, Any]:
    """Reuse the repository's existing case/scoring evaluator without live calls."""

    evaluator_path = (
        Path(repo_root) / "tests" / "skill-validator" / "web2_vuln_ab_eval.py"
    )
    spec = spec_from_file_location("web2_vuln_ab_eval_for_runner", evaluator_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load evaluator: {evaluator_path}")
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.evaluate_cases(Path(repo_root), Path(cases_path))


def _parse_truths(values: list[str]) -> dict[str, str]:
    truths: dict[str, str] = {}
    for value in values:
        case_id, separator, label = value.partition("=")
        if not separator or not case_id or not label:
            raise ValueError(f"truth must be CASE_ID=LABEL: {value!r}")
        truths[case_id] = label
    return truths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize offline Skill A/B JSONL rows."
    )
    parser.add_argument("input", type=Path, help="JSONL rows; no live model is invoked")
    parser.add_argument("--truth", action="append", default=[], metavar="CASE_ID=LABEL")
    parser.add_argument(
        "--json", action="store_true", help="emit JSON instead of a short text summary"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return exit code 2 when rows are invalid or pairs are incomplete",
    )
    args = parser.parse_args(argv)
    result = summarize_rows(
        load_jsonl(args.input), case_truths=_parse_truths(args.truth)
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(
            f"rows={result['row_count']} valid={result['valid_row_count']} invalid={result['invalid_row_count']}"
        )
        for condition in sorted(CONDITIONS):
            stats = result["conditions"][condition]
            print(f"{condition}: TPR={stats['tpr']} FPR={stats['fpr']}")
        print(f"paired_delta={result['paired_delta']['accuracy']}")
    if args.strict and (
        not result["row_count"]
        or result["invalid_row_count"]
        or result["unpaired_pair_count"]
    ):
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
