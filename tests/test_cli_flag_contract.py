"""CLI flag contract: documented invocations must parse against real argparse definitions.

Lab e2e (2026-09-12) 实测了两类同一形态的真实缺陷：`claim --template` 与
`distill_target prompt --json` 都是文档/代码写了、argparse 没定义——AI 按文档
调用直接 argparse 报错，返工占靶场开销 14%。本测试扫 `commands/`、
`docs/autopilot-lanes.md`、`docs/tool-index.md`、`docs/evidence-runners.md`、
`rules/coverage-gate.md` 中的 `tools/<x>.py ... --flag` 调用形态，对账各工具
真实 argparse 定义。对账只看「带前导 `--` 的 token 是否被该工具接受」，
不验证语义组合（那是各 owner 自己的测试职责）。
"""

from __future__ import annotations

import argparse
import importlib
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# 文档来源 = 权威调用形态的书写位置（canonical references 中的命令面）
DOC_SOURCES = [
    REPO_ROOT / "commands",
    REPO_ROOT / "docs" / "autopilot-lanes.md",
    REPO_ROOT / "docs" / "tool-index.md",
    REPO_ROOT / "docs" / "evidence-runners.md",
    REPO_ROOT / "rules" / "coverage-gate.md",
]

# 暴露 build_parser() 的 owner 工具（新增 owner 工具时补进这里）
PARSER_TOOLS = (
    "action_queue",
    "checkpoint",
    "context_pack",
    "distill_target",
    "evidence_ledger",
    "probe",
    "validate",
    "validation_runner",
)

# 文档行内出现、但不是该工具 CLI flag 的 token（占位符/值/别的工具的 flag 经 shell 透传）
_KNOWN_NON_FLAGS = {"--"}


def _iter_doc_lines() -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    for source in DOC_SOURCES:
        if source.is_dir():
            files = sorted(source.glob("*.md"))
        elif source.is_file():
            files = [source]
        else:
            continue
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                lines.append((f"{path.relative_to(REPO_ROOT)}", line))
    return lines


# 否定句里的 flag 不是调用形态（如 "it never accepts --decision-json"）
_NEGATION_WINDOW = 48
_NEGATION_WORDS = ("never accepts", "does not accept", "not accept", "never take")


def _documented_invocations() -> list[tuple[str, str, str]]:
    """Return (doc, tool, flag) for every documented `tools/<x>.py ... --flag` mention."""
    invocations: list[tuple[str, str, str]] = []
    pattern = re.compile(r"tools/([a-z0-9_]+)\.py\b")
    for doc, line in _iter_doc_lines():
        match = pattern.search(line)
        if not match:
            continue
        tool = match.group(1)
        if tool not in PARSER_TOOLS:
            continue
        # 只取该行内 tool 名之后的 flag tokens，避免吞并同一行的其他工具 flag
        tail = line[match.end():]
        for flag in re.findall(r"(?<![\w-])(--[a-z0-9][a-z0-9-]*)", tail):
            if flag in _KNOWN_NON_FLAGS:
                continue
            # 跳过否定句（该 flag 前的窗口里出现否定词 = 文档在声明"不接受"）
            prefix = tail[: tail.find(flag)]
            if any(word in prefix[-_NEGATION_WINDOW:] for word in _NEGATION_WORDS):
                continue
            invocations.append((doc, tool, flag))
    return invocations


@pytest.fixture(scope="module")
def parsers() -> dict[str, argparse.ArgumentParser]:
    loaded: dict[str, argparse.ArgumentParser] = {}
    for tool in PARSER_TOOLS:
        module = importlib.import_module(f"tools.{tool}")
        loaded[tool] = module.build_parser()
    return loaded


def _accepted_flags(parser: argparse.ArgumentParser) -> set[str]:
    flags: set[str] = set()
    def walk(p: argparse.ArgumentParser) -> None:
        for action in p._actions:
            flags.update(action.option_strings)
            if isinstance(action, argparse._SubParsersAction):
                for sub in action.choices.values():
                    walk(sub)
    walk(parser)
    return flags


@pytest.mark.parametrize(
    "doc,tool,flag",
    _documented_invocations(),
    ids=lambda value: str(value),
)
def test_documented_flag_exists_in_argparse(doc: str, tool: str, flag: str, parsers) -> None:
    """文档写的每个 flag 必须被对应工具的 argparse 真实接受。"""
    assert flag in _accepted_flags(parsers[tool]), (
        f"{doc} documents `{tool}.py {flag}` but argparse does not define it "
        f"(past real bugs: claim --template, distill prompt --json)"
    )


def test_contract_covers_documents() -> None:
    """对账必须真的扫到了文档（防止 glob 失效导致测试静默变空）。"""
    invocations = _documented_invocations()
    assert len(invocations) > 20, f"expected documented tool invocations, got {len(invocations)}"
    assert {"--target", "--json"} <= {flag for _, _, flag in invocations}
