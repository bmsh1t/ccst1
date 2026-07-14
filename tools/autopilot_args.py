#!/usr/bin/env python3
"""为 Claude inline `/autopilot` 提供确定性参数契约。"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any, Sequence

try:
    from tools.target_paths import classify_target
except ModuleNotFoundError:  # 兼容 `python3 tools/autopilot_args.py` 直接执行
    from target_paths import classify_target


SCHEMA_VERSION = 3
# target + auth pair + quick + deep + cadence + max-lanes pair
MAX_EFFECTIVE_TOKENS = 8
MAX_CAPTURED_TOKENS = MAX_EFFECTIVE_TOKENS + 1
MAX_LANES = 32

CADENCE_FLAGS = {
    "--paranoid": "paranoid",
    "--normal": "normal",
    "--yolo": "yolo",
}
CHECKPOINT_POLICIES = {
    "paranoid": "frequent",
    "normal": "batched",
    "yolo": "minimal",
}
CHECKPOINT_TRIGGERS = {
    "paranoid": "checkpoint after every substantive state change",
    "normal": "checkpoint after each coherent evidence-lane batch",
    "yolo": "checkpoint only on blocker, handoff, or finish",
}
BOOLEAN_FLAGS = {"--quick": "quick", "--deep": "deep"}
LEGACY_BOOLEAN_FLAGS = {
    "--agent",
    "--calibrate-patterns",
    "--parallel",
    "--parallel-hypotheses",
    "--self-review",
    "--vision",
}
LEGACY_VALUE_FLAGS = {
    "--max-parallel",
    "--max-screenshots",
    "--resume",
    "--worker-timeout-secs",
}
LEGACY_RUNTIME_HINT = (
    "Use `python3 agent.py --target <target> ...` for legacy local-agent flags; "
    "`python3 tools/hunt.py --target <target> --agent` remains the baseline entry."
)


def cadence_from_namespace(namespace: Namespace | Any) -> str:
    """统一解析 direct CLI 的 checkpoint cadence，默认使用 paranoid。"""
    if getattr(namespace, "yolo", False):
        return "yolo"
    if getattr(namespace, "normal", False):
        return "normal"
    return "paranoid"


def _error(code: str, message: str, **details: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"code": code, "message": message}
    payload.update(details)
    return payload


def _effective_argv(argv: Sequence[str]) -> list[str]:
    """移除 Claude 为未使用 positional slots 注入的空字符串。"""
    return [str(token) for token in argv if str(token).strip()]


def _legacy_flag_name(token: str) -> str | None:
    flag_name = token.split("=", 1)[0]
    if flag_name in LEGACY_BOOLEAN_FLAGS or flag_name in LEGACY_VALUE_FLAGS:
        return flag_name
    return None


def _resolve_target(target_input: str, cwd: str | os.PathLike[str] | None) -> dict[str, str]:
    candidate = target_input
    if cwd and not os.path.isabs(candidate):
        relative_path = Path(cwd) / candidate
        if relative_path.is_file():
            candidate = str(relative_path.resolve())
    target_info = classify_target(candidate)
    return {
        "target": str(target_info["target"]),
        "target_kind": str(target_info["kind"]),
    }


def _resolve_auth_file(
    auth_file_input: str,
    cwd: str | os.PathLike[str] | None,
) -> str:
    """按 slash invocation cwd 解析静态 auth 文件，并在 active tool 前失败。"""
    path = Path(auth_file_input).expanduser()
    if not path.is_absolute():
        path = Path(cwd or Path.cwd()) / path
    resolved = path.resolve()
    if not resolved.is_file():
        raise ValueError(f"auth file is not a readable file: {auth_file_input}")
    return str(resolved)


def parse_autopilot_args(
    argv: Sequence[str],
    cwd: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """解析 inline 参数；错误也返回稳定 JSON，避免模型自行猜测。"""
    effective_argv = _effective_argv(argv)
    errors: list[dict[str, Any]] = []
    targets: list[str] = []
    cadence_flags: list[str] = []
    auth_file_inputs: list[str] = []
    max_lanes_inputs: list[str] = []
    quick = False
    deep = False

    if len(effective_argv) > MAX_EFFECTIVE_TOKENS:
        errors.append(
            _error(
                "overflow",
                f"Inline /autopilot accepts at most {MAX_EFFECTIVE_TOKENS} tokens.",
                maximum=MAX_EFFECTIVE_TOKENS,
                captured=len(effective_argv),
            )
        )

    index = 0
    while index < len(effective_argv):
        token = effective_argv[index]
        if token in CADENCE_FLAGS:
            if token not in cadence_flags:
                cadence_flags.append(token)
            index += 1
            continue
        if token in BOOLEAN_FLAGS:
            if BOOLEAN_FLAGS[token] == "quick":
                quick = True
            else:
                deep = True
            index += 1
            continue
        if token == "--auth-file":
            if index + 1 >= len(effective_argv) or effective_argv[index + 1].startswith("-"):
                errors.append(
                    _error(
                        "missing_auth_file_value",
                        "--auth-file requires one JSON or .env file path.",
                        token=token,
                    )
                )
                index += 1
            else:
                auth_file_inputs.append(effective_argv[index + 1])
                index += 2
            continue
        if token.startswith("--auth-file="):
            value = token.split("=", 1)[1].strip()
            if value:
                auth_file_inputs.append(value)
            else:
                errors.append(
                    _error(
                        "missing_auth_file_value",
                        "--auth-file requires one JSON or .env file path.",
                        token=token,
                    )
                )
            index += 1
            continue

        if token == "--max-lanes":
            next_value = effective_argv[index + 1] if index + 1 < len(effective_argv) else ""
            if (
                not next_value
                or (
                    next_value.startswith("-")
                    and not re.fullmatch(r"-\d+", next_value)
                )
            ):
                errors.append(
                    _error(
                        "missing_max_lanes_value",
                        "--max-lanes requires a positive integer value.",
                        token=token,
                    )
                )
                index += 1
            else:
                max_lanes_inputs.append(effective_argv[index + 1])
                index += 2
            continue
        if token.startswith("--max-lanes="):
            value = token.split("=", 1)[1].strip()
            if value:
                max_lanes_inputs.append(value)
            else:
                errors.append(
                    _error(
                        "missing_max_lanes_value",
                        "--max-lanes requires a positive integer value.",
                        token=token,
                    )
                )
            index += 1
            continue

        legacy_flag = _legacy_flag_name(token)
        if legacy_flag:
            errors.append(
                _error(
                    "legacy_only_flag",
                    f"{legacy_flag} is not available in inline /autopilot. {LEGACY_RUNTIME_HINT}",
                    token=token,
                    hint=LEGACY_RUNTIME_HINT,
                )
            )
            if (
                legacy_flag in LEGACY_VALUE_FLAGS
                and "=" not in token
                and index + 1 < len(effective_argv)
                and not effective_argv[index + 1].startswith("-")
            ):
                index += 2
            else:
                index += 1
            continue

        if token.startswith("-"):
            errors.append(
                _error(
                    "unknown_flag",
                    f"Unsupported inline /autopilot flag: {token}",
                    token=token,
                )
            )
        else:
            targets.append(token)
        index += 1

    if len(cadence_flags) > 1:
        errors.append(
            _error(
                "cadence_conflict",
                "Choose exactly one of --paranoid, --normal, or --yolo.",
                flags=cadence_flags,
            )
        )
    if len(targets) > 1:
        errors.append(
            _error(
                "multiple_targets",
                "Inline /autopilot accepts exactly one target.",
                targets=targets,
            )
        )
    if len(auth_file_inputs) > 1:
        errors.append(
            _error(
                "auth_file_conflict",
                "Inline /autopilot accepts at most one --auth-file path.",
                paths=auth_file_inputs,
            )
        )

    max_lanes: int | None = None
    if len(max_lanes_inputs) > 1:
        errors.append(
            _error(
                "max_lanes_conflict",
                "Inline /autopilot accepts at most one --max-lanes value.",
                values=max_lanes_inputs,
            )
        )
    elif max_lanes_inputs:
        raw_max_lanes = max_lanes_inputs[0]
        try:
            parsed_max_lanes = int(raw_max_lanes)
        except ValueError:
            parsed_max_lanes = 0
        if (
            not raw_max_lanes.isdigit()
            or parsed_max_lanes < 1
            or parsed_max_lanes > MAX_LANES
        ):
            errors.append(
                _error(
                    "invalid_max_lanes",
                    f"--max-lanes must be an integer from 1 to {MAX_LANES}.",
                    value=raw_max_lanes,
                    maximum=MAX_LANES,
                )
            )
        else:
            max_lanes = parsed_max_lanes
    if max_lanes is not None and not deep:
        errors.append(
            _error(
                "max_lanes_requires_deep",
                "--max-lanes is valid only together with --deep.",
            )
        )

    cadence = CADENCE_FLAGS[cadence_flags[0]] if cadence_flags else "paranoid"
    target_input = targets[0] if len(targets) == 1 else None
    target = None
    target_kind = None
    target_shell = None
    seed_url = None
    seed_url_shell = None
    if target_input is not None:
        try:
            resolved = _resolve_target(target_input, cwd)
        except (OSError, ValueError) as exc:
            errors.append(
                _error(
                    "invalid_target",
                    f"Invalid /autopilot target: {exc}",
                    target=target_input,
                )
            )
        else:
            target = resolved["target"]
            target_kind = resolved["target_kind"]
            target_shell = shlex.quote(target)
            if "://" in target_input:
                seed_url = target_input
                seed_url_shell = shlex.quote(seed_url)

    auth_file = None
    auth_file_shell = None
    if len(auth_file_inputs) == 1:
        try:
            auth_file = _resolve_auth_file(auth_file_inputs[0], cwd)
        except (OSError, ValueError) as exc:
            errors.append(
                _error(
                    "invalid_auth_file",
                    f"Invalid /autopilot auth file: {exc}",
                    path=auth_file_inputs[0],
                )
            )
        else:
            auth_file_shell = shlex.quote(auth_file)

    if errors:
        action = "stop_invalid_arguments"
    elif target_input is None:
        action = "ask_target"
        errors.append(
            _error(
                "missing_target",
                "Provide exactly one target for inline /autopilot.",
            )
        )
    else:
        action = "continue"

    return {
        "schema_version": SCHEMA_VERSION,
        "valid": action == "continue",
        "action": action,
        "argv": effective_argv,
        "target_input": target_input,
        "target": target,
        "target_kind": target_kind,
        "target_shell": target_shell,
        "seed_url": seed_url,
        "seed_url_shell": seed_url_shell,
        "auth_file": auth_file,
        "auth_file_shell": auth_file_shell,
        "hunt_auth_flags": ["--auth-file", auth_file] if auth_file else [],
        "cadence": cadence,
        "checkpoint_policy": CHECKPOINT_POLICIES[cadence],
        "checkpoint_trigger": CHECKPOINT_TRIGGERS[cadence],
        "quick": quick,
        "deep": deep,
        "max_lanes": max_lanes,
        "invocation_batch": {
            "bounded": bool(deep and max_lanes is not None),
            "max_lanes": max_lanes,
            "handoff": (
                "checkpoint_and_handoff_after_max_lanes"
                if deep and max_lanes is not None
                else "normal_finish_condition"
            ),
        },
        "recon_flags": ["--quick"] if quick else [],
        "errors": errors,
    }


def render_autopilot_args_json(payload: dict[str, Any]) -> str:
    """输出适合 Claude dynamic expansion 的单行稳定 JSON。"""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def main(argv: Sequence[str] | None = None) -> int:
    cli_argv = list(sys.argv[1:] if argv is None else argv)
    compact = bool(cli_argv and cli_argv[0] == "--json")
    if compact:
        cli_argv.pop(0)
    if cli_argv and cli_argv[0] == "--":
        cli_argv.pop(0)

    payload = parse_autopilot_args(cli_argv)
    if compact:
        print(render_autopilot_args_json(payload))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
