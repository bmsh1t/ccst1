#!/usr/bin/env python3
"""Collect paired Claude CLI A/B rows for the existing offline scorer.

The collector is intentionally a thin subprocess adapter.  It does not score
answers, persist Claude output, or own a runtime state machine.  The caller
provides a staged HOME so the only treatment difference is whether Claude
loads its Skills.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[2]
CONDITIONS = ("skills_off", "skills_on")
DEFAULT_VERDICTS = ("vulnerable", "safe")
BEHAVIOR_BOOL_FIELDS = (
    "hypothesis_selected",
    "action_selected",
    "tool_choice_valid",
    "evidence_complete",
    "duplicate_action",
    "invalid_route",
    "recovery_success",
    "unsupported_claim",
)
BEHAVIOR_NUMERIC_FIELDS = ("coverage_progress",)

if str(Path(__file__).parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).parent))
from ab_runner import load_jsonl  # noqa: E402


def _parse_csv(value: str, *, name: str) -> list[str]:
    values = [item.strip() for item in value.split(",") if item.strip()]
    if not values:
        raise ValueError(f"{name} must not be empty")
    return values


def _load_cases(path: Path) -> list[dict[str, Any]]:
    rows = load_jsonl(path)
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        if "_jsonl_error" in row:
            raise ValueError(str(row["_jsonl_error"]))
        case_id = row.get("case_id", row.get("id"))
        prompt = row.get("prompt", row.get("task"))
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"case line {index}: case_id must be a non-empty string")
        case_id = case_id.strip()
        if case_id in seen:
            raise ValueError(f"case line {index}: duplicate case_id: {case_id}")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(f"case line {index}: prompt must be a non-empty string")
        oracle_label = row.get("oracle_label", row.get("expected", row.get("truth")))
        if not isinstance(oracle_label, str) or not oracle_label.strip():
            raise ValueError(f"case line {index}: oracle_label is required")
        oracle_status = row.get("oracle_status", "passed")
        if not isinstance(oracle_status, str) or not oracle_status.strip():
            raise ValueError(f"case line {index}: oracle_status must be a string")
        seen.add(case_id)
        cases.append(
            {
                "case_id": case_id,
                "prompt": prompt,
                "oracle_label": oracle_label.strip(),
                "oracle_status": oracle_status.strip(),
            }
        )
    if not cases:
        raise ValueError(f"case file is empty: {path}")
    return cases


def _verdict_schema(verdicts: list[str]) -> dict[str, Any]:
    if len(verdicts) != 2 or len(set(verdicts)) != 2:
        raise ValueError("verdicts must contain exactly two distinct labels")
    return {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": verdicts},
            **{field: {"type": "boolean"} for field in BEHAVIOR_BOOL_FIELDS},
            "coverage_progress": {"type": "number", "minimum": 0},
        },
        "required": ["verdict"],
        "additionalProperties": False,
    }


def _prompt(case_prompt: str, verdicts: list[str]) -> str:
    labels = ", ".join(verdicts)
    return (
        f"{case_prompt}\n\n"
        "Return your final binary decision in the structured output field "
        f"`verdict`, using exactly one of: {labels}. "
        "Fill optional behavior fields only when the task directly provides "
        "the observation; omit fields that are not observable."
    )


def build_command(
    claude: str | Path,
    prompt: str,
    *,
    condition: str,
    verdicts: list[str],
    model: str | None,
    tools: str,
    setting_sources: str,
    permission_mode: str,
    max_turns: int,
    max_budget_usd: str | None,
) -> list[str]:
    if condition not in CONDITIONS:
        raise ValueError(f"unknown condition: {condition}")
    command = [
        str(claude),
        "-p",
        _prompt(prompt, verdicts),
        "--output-format",
        "json",
        "--json-schema",
        json.dumps(_verdict_schema(verdicts), separators=(",", ":")),
        "--setting-sources",
        setting_sources,
        "--tools",
        tools,
        "--permission-mode",
        permission_mode,
        "--max-turns",
        str(max_turns),
        "--no-session-persistence",
    ]
    if model:
        command.extend(("--model", model))
    if max_budget_usd is not None:
        command.extend(("--max-budget-usd", max_budget_usd))
    if condition == "skills_off":
        command.append("--disable-slash-commands")
    return command


def _number(value: Any, *, integer: bool = False) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value < 0:
        return None
    if integer:
        return int(value)
    return float(value)


def parse_result(stdout: str, *, duration_ms: float) -> dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "verdict": "unknown",
            "agent_error": "invalid_json",
            "duration_ms": duration_ms,
        }
    if not isinstance(payload, Mapping):
        return {
            "verdict": "unknown",
            "agent_error": "result_not_object",
            "duration_ms": duration_ms,
        }

    structured = payload.get("structured_output")
    verdict = structured.get("verdict") if isinstance(structured, Mapping) else None
    if not isinstance(verdict, str) or not verdict.strip():
        verdict = "unknown"
        error = "structured_verdict_missing"
    else:
        error = None
    usage = payload.get("usage")
    usage = usage if isinstance(usage, Mapping) else {}
    token_values = [
        _number(usage.get("input_tokens"), integer=True),
        _number(usage.get("output_tokens"), integer=True),
    ]
    observed_tokens = [value for value in token_values if value is not None]
    tokens = sum(observed_tokens) if observed_tokens else None
    result: dict[str, Any] = {
        "verdict": verdict.strip(),
        "turns": _number(payload.get("num_turns"), integer=True),
        "tokens": tokens,
        "cost_usd": _number(payload.get("total_cost_usd")),
        "duration_ms": _number(payload.get("duration_ms")) or duration_ms,
    }
    if payload.get("is_error"):
        result["verdict"] = "unknown"
        result["agent_error"] = "agent_error"
    elif error:
        result["agent_error"] = error
    for field in BEHAVIOR_BOOL_FIELDS:
        value = structured.get(field) if isinstance(structured, Mapping) else None
        if isinstance(value, bool):
            result[field] = value
    value = structured.get("coverage_progress") if isinstance(structured, Mapping) else None
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
        result["coverage_progress"] = value
    return result


def _run_case(
    claude: str | Path,
    case: Mapping[str, Any],
    *,
    condition: str,
    rep: int,
    verdicts: list[str],
    model: str | None,
    tools: str,
    setting_sources: str,
    permission_mode: str,
    max_turns: int,
    max_budget_usd: str | None,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    command = build_command(
        claude,
        str(case["prompt"]),
        condition=condition,
        verdicts=verdicts,
        model=model,
        tools=tools,
        setting_sources=setting_sources,
        permission_mode=permission_mode,
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
    )
    started = time.monotonic()
    error: str | None = None
    parsed: dict[str, Any]
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        completed = None
        error = "timeout"
    except OSError:
        completed = None
        error = "launch_error"
    duration_ms = round((time.monotonic() - started) * 1000, 3)

    if error:
        parsed = {"verdict": "unknown", "duration_ms": duration_ms}
    elif completed is None or completed.returncode != 0:
        parsed = {"verdict": "unknown", "duration_ms": duration_ms}
        error = "nonzero_exit"
    else:
        parsed = parse_result(completed.stdout, duration_ms=duration_ms)
        error = parsed.pop("agent_error", None)

    row = {
        "case_id": case["case_id"],
        "condition": condition,
        "rep": rep,
        "verdict": parsed.get("verdict", "unknown"),
        "oracle_status": case["oracle_status"],
        "oracle_label": case["oracle_label"],
        "turns": parsed.get("turns"),
        "tokens": parsed.get("tokens"),
        "cost_usd": parsed.get("cost_usd"),
        "duration_ms": parsed.get("duration_ms", duration_ms),
    }
    for field in (*BEHAVIOR_BOOL_FIELDS, *BEHAVIOR_NUMERIC_FIELDS):
        if field in parsed:
            row[field] = parsed[field]
    if error:
        row["agent_error"] = error
    return row


def _append_row(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def _row_key(row: Mapping[str, Any]) -> tuple[str, str, int] | None:
    if not {"case_id", "condition", "rep"} <= row.keys():
        return None
    try:
        return (str(row["case_id"]), str(row["condition"]), int(row["rep"]))
    except (TypeError, ValueError):
        return None


def _row_is_retryable(row: Mapping[str, Any]) -> bool:
    return bool(row.get("agent_error")) or str(row.get("verdict") or "").strip().lower() == "unknown"


def _replace_row(path: Path, row: Mapping[str, Any]) -> None:
    """Replace one retryable attempt so strict A/B pairing sees one row per key."""
    key = _row_key(row)
    if key is None or not path.exists():
        _append_row(path, row)
        return
    kept: list[str] = []
    replaced = False
    for line in path.read_text(encoding="utf-8").splitlines(keepends=True):
        try:
            existing = json.loads(line)
        except json.JSONDecodeError:
            kept.append(line)
            continue
        if isinstance(existing, Mapping) and _row_key(existing) == key and _row_is_retryable(existing):
            if not replaced:
                kept.append(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
                replaced = True
            continue
        kept.append(line)
    if not replaced:
        kept.append(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write("".join(kept))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def _existing_keys(path: Path) -> set[tuple[str, str, int]]:
    if not path.exists():
        return set()
    keys: set[tuple[str, str, int]] = set()
    for row in load_jsonl(path):
        if not isinstance(row, Mapping) or _row_is_retryable(row):
            continue
        key = _row_key(row)
        if key is not None:
            keys.add(key)
    return keys


def _git_revision(cwd: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _claude_version(claude: str | Path, env: Mapping[str, str]) -> str | None:
    try:
        result = subprocess.run(
            [str(claude), "--version"],
            env=dict(env),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = (result.stdout or result.stderr).strip()
    return value or None


def _write_manifest(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(payload), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"
    except OSError:
        return None


def _runtime_provenance(cwd: Path, home: Path, config_dir: Path) -> dict[str, Any]:
    runtime_root = home / ".claude"
    try:
        from tools.runtime_doctor import compare_runtime

        doctor = compare_runtime(cwd, runtime_root)
        doctor_projection = {
            "clean": bool(doctor.get("clean")),
            "critical_clean": bool(doctor.get("critical_clean")),
            "drift_count": int(doctor.get("drift_count", 0) or 0),
            "critical_drift_count": int(doctor.get("critical_drift_count", 0) or 0),
        }
    except (OSError, TypeError, ValueError, ImportError) as exc:
        doctor_projection = {"status": "unknown", "error": str(exc)[:160]}
    install_script = cwd / "install.sh"
    return {
        "staged_home": str(home),
        "xdg_config_home": str(config_dir),
        "runtime_root": str(runtime_root),
        "install_script": {
            "path": str(install_script),
            "sha256": _sha256_file(install_script),
        },
        "runtime_doctor": doctor_projection,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect paired Claude CLI Skill A/B rows."
    )
    parser.add_argument(
        "cases", type=Path, help="JSONL cases with case_id, prompt, and oracle_label"
    )
    parser.add_argument("--output", type=Path, required=True, help="output JSONL rows")
    parser.add_argument(
        "--manifest", type=Path, help="run metadata JSON; defaults beside output"
    )
    parser.add_argument(
        "--home",
        type=Path,
        required=True,
        help="staged HOME containing the Claude runtime",
    )
    parser.add_argument("--cwd", type=Path, default=BASE_DIR)
    parser.add_argument("--claude", default=shutil.which("claude") or "claude")
    parser.add_argument("--model")
    parser.add_argument(
        "--tools", default="", help="same Claude tool profile for both arms"
    )
    parser.add_argument("--setting-sources", default="user")
    parser.add_argument("--permission-mode", default="auto")
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--max-budget-usd")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--conditions", default=",".join(CONDITIONS))
    parser.add_argument("--verdicts", default=",".join(DEFAULT_VERDICTS))
    parser.add_argument(
        "--append", action="store_true", help="resume an existing output file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print arm/rep commands without invoking Claude",
    )
    args = parser.parse_args(argv)

    try:
        if args.repetitions < 1 or args.max_turns < 1 or args.timeout <= 0:
            raise ValueError("repetitions, max-turns, and timeout must be positive")
        conditions = _parse_csv(args.conditions, name="conditions")
        if any(condition not in CONDITIONS for condition in conditions):
            raise ValueError(f"conditions must be from: {', '.join(CONDITIONS)}")
        verdicts = _parse_csv(args.verdicts, name="verdicts")
        _verdict_schema(verdicts)
        cases = _load_cases(args.cases)
        home = args.home.expanduser().resolve()
        cwd = args.cwd.resolve()
        if not home.is_dir():
            raise ValueError(f"staged HOME does not exist: {home}")
        if not cwd.is_dir():
            raise ValueError(f"cwd does not exist: {cwd}")
        if args.output.exists() and not args.append and not args.dry_run:
            raise ValueError(f"output exists; use --append to resume: {args.output}")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    config_dir = home / ".config"
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config_dir),
            "CLAUDE_CONFIG_DIR": str(home / ".claude"),
        }
    )
    manifest_path = args.manifest or args.output.with_suffix(".manifest.json")
    if not args.dry_run and not (args.append and manifest_path.exists()):
        try:
            _write_manifest(
                manifest_path,
                {
                    "schema_version": 1,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "cases": str(args.cases.resolve()),
                    "cwd": str(cwd),
                    "model": args.model or "cli-default",
                    "claude": str(args.claude),
                    "claude_version": _claude_version(args.claude, env),
                    "tools": args.tools,
                    "setting_sources": args.setting_sources,
                    "permission_mode": args.permission_mode,
                    "conditions": conditions,
                    "repetitions": args.repetitions,
                    "verdicts": verdicts,
                    "git_revision": _git_revision(cwd),
                    "provenance": _runtime_provenance(cwd, home, config_dir),
                },
            )
        except OSError as exc:
            print(f"manifest write failed: {manifest_path}: {exc}", file=sys.stderr)
            return 2

    completed_keys = _existing_keys(args.output) if args.append else set()
    agent_errors = 0
    for rep in range(1, args.repetitions + 1):
        for case in cases:
            for condition in conditions:
                key = (str(case["case_id"]), condition, rep)
                if key in completed_keys:
                    continue
                command = build_command(
                    args.claude,
                    str(case["prompt"]),
                    condition=condition,
                    verdicts=verdicts,
                    model=args.model,
                    tools=args.tools,
                    setting_sources=args.setting_sources,
                    permission_mode=args.permission_mode,
                    max_turns=args.max_turns,
                    max_budget_usd=args.max_budget_usd,
                )
                if args.dry_run:
                    print(
                        json.dumps(
                            {
                                "case_id": case["case_id"],
                                "condition": condition,
                                "rep": rep,
                                "argv": command,
                            },
                            ensure_ascii=False,
                        )
                    )
                    continue
                row = _run_case(
                    args.claude,
                    case,
                    condition=condition,
                    rep=rep,
                    verdicts=verdicts,
                    model=args.model,
                    tools=args.tools,
                    setting_sources=args.setting_sources,
                    permission_mode=args.permission_mode,
                    max_turns=args.max_turns,
                    max_budget_usd=args.max_budget_usd,
                    cwd=cwd,
                    env=env,
                    timeout=args.timeout,
                )
                agent_errors += int("agent_error" in row)
                try:
                    if args.append:
                        _replace_row(args.output, row)
                    else:
                        _append_row(args.output, row)
                except OSError as exc:
                    print(f"row write failed: {args.output}: {exc}", file=sys.stderr)
                    return 2
                completed_keys.add(key)
                print(
                    json.dumps(
                        {
                            key: row[key]
                            for key in ("case_id", "condition", "rep", "verdict")
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
    return 2 if agent_errors else 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
