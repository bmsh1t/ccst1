#!/usr/bin/env python3
"""为 Claude inline `/autopilot` 提供确定性参数契约。"""

from __future__ import annotations

import json
import os
import shlex
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any, Sequence

try:
    from tools.target_paths import classify_target
except ModuleNotFoundError:  # 兼容 `python3 tools/autopilot_args.py` 直接执行
    from target_paths import classify_target


SCHEMA_VERSION = 1
MAX_EFFECTIVE_TOKENS = 6
MAX_CAPTURED_TOKENS = MAX_EFFECTIVE_TOKENS + 1

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


def parse_autopilot_args(
    argv: Sequence[str],
    cwd: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """解析 inline 参数；错误也返回稳定 JSON，避免模型自行猜测。"""
    effective_argv = _effective_argv(argv)
    errors: list[dict[str, Any]] = []
    targets: list[str] = []
    cadence_flags: list[str] = []
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

    cadence = CADENCE_FLAGS[cadence_flags[0]] if cadence_flags else "paranoid"
    target_input = targets[0] if len(targets) == 1 else None
    target = None
    target_kind = None
    target_shell = None
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
        "cadence": cadence,
        "checkpoint_policy": CHECKPOINT_POLICIES[cadence],
        "quick": quick,
        "deep": deep,
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
