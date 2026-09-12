"""request_diff: public entry must import from both execution contexts.

回归（外部评审 2026-09-12 复现）：`expected_fact_vocabulary()` 内的裸
`from validation_runner import WIRE_FACT_NAMES` 只在 sys.path 含 tools/ 时成立
（直接脚本执行/测试注入），从包根 `from tools.request_diff import ...` 调用
直接 ModuleNotFoundError。validate.py / report_generator.py 同场景都用双路径
try/except，本文件曾漏写。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_expected_fact_vocabulary_from_package_root():
    """包根上下文（sys.path 只有 repo root）必须可调用，不得依赖 tools/ 注入。"""
    code = (
        "import sys; sys.path.insert(0, '.')\n"
        "from tools.request_diff import expected_fact_vocabulary\n"
        "vocab = expected_fact_vocabulary()\n"
        "assert vocab, 'vocabulary must not be empty'\n"
        "print(len(vocab))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.strip()) > 0


def test_expected_fact_vocabulary_from_outside_cwd():
    """cwd 在仓库外时同样必须可调用（评审复现条件）。"""
    code = (
        "import sys; sys.path.insert(0, r'" + str(REPO_ROOT) + "')\n"
        "from tools.request_diff import expected_fact_vocabulary\n"
        "assert expected_fact_vocabulary()\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path("/tmp"),
        capture_output=True,
        text=True,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
