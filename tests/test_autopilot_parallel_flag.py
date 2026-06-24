"""tests/test_autopilot_parallel_flag.py — B6 R7/R8 CLI flag wiring."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.parallel_workers import (
    coerce_max_parallel,
    DEFAULT_MAX_PARALLEL,
    PARANOID_MAX_PARALLEL,
    YOLO_MAX_PARALLEL,
)


def _build_test_parser() -> argparse.ArgumentParser:
    """Build a parser containing the new --parallel flags only."""
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--paranoid", action="store_true")
    mode.add_argument("--normal", action="store_true")
    mode.add_argument("--yolo", action="store_true")
    parser.add_argument("--parallel", action="store_true")
    parser.add_argument("--max-parallel", type=int, default=3)
    parser.add_argument("--worker-timeout-secs", type=int, default=300)
    return parser


class TestArgparseDefaults:
    def test_parallel_defaults_off(self):
        ns = _build_test_parser().parse_args([])
        assert ns.parallel is False
        assert ns.max_parallel == 3
        assert ns.worker_timeout_secs == 300

    def test_max_parallel_can_be_overridden(self):
        ns = _build_test_parser().parse_args(["--max-parallel", "5"])
        assert ns.max_parallel == 5

    def test_parallel_and_paranoid_can_coexist(self):
        ns = _build_test_parser().parse_args(["--parallel", "--paranoid"])
        assert ns.parallel is True
        assert ns.paranoid is True


class TestModeCoercionEdgeCases:
    def test_paranoid_with_parallel_still_caps_at_one(self):
        # B6 R8 — paranoid forces --max-parallel 1
        assert coerce_max_parallel(8, "paranoid") == 1

    def test_normal_default_is_three(self):
        # B6 C4 — default cap of 3 even when operator omits flag entirely
        assert coerce_max_parallel(DEFAULT_MAX_PARALLEL, "normal") == DEFAULT_MAX_PARALLEL

    def test_yolo_can_lift_to_eight(self):
        assert coerce_max_parallel(8, "yolo") == YOLO_MAX_PARALLEL

    def test_unknown_mode_defaults_to_normal_cap(self):
        assert coerce_max_parallel(99, "unknown_mode") == DEFAULT_MAX_PARALLEL


def test_paranoid_max_parallel_constant_is_one():
    """C4 invariant: paranoid hard floor at 1."""
    assert PARANOID_MAX_PARALLEL == 1


def test_default_max_parallel_is_three():
    """C4 invariant: default is 3."""
    assert DEFAULT_MAX_PARALLEL == 3


def test_yolo_max_parallel_is_eight():
    """B6 R7 invariant: yolo allows up to 8."""
    assert YOLO_MAX_PARALLEL == 8


def test_agent_py_imports_parallel_module():
    """sanity: agent.py CLI section references --parallel; module is reachable."""
    text = (REPO_ROOT / "agent.py").read_text(encoding="utf-8")
    assert "--parallel" in text
    assert "--max-parallel" in text
    assert "--worker-timeout-secs" in text


def test_autopilot_md_documents_new_flags():
    """B6 AC bullet — commands/autopilot.md mentions the new flags."""
    md = (REPO_ROOT / "commands" / "autopilot.md").read_text(encoding="utf-8")
    assert "--parallel" in md, "commands/autopilot.md missing --parallel docs"
    assert "--max-parallel" in md, "commands/autopilot.md missing --max-parallel docs"
