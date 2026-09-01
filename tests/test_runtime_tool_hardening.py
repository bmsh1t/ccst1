"""Runtime tool hardening regression tests.

这些测试只做本地静态/CLI smoke 检查，不访问外部目标。
"""

import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_cli_help_does_not_require_credentials_or_network() -> None:
    """核心工具的 help 应可离线查看，不能因缺 env/依赖触发真实请求。"""
    commands = [
        ("python3", "tools/scope_checker.py", "--help"),
        ("python3", "tools/validate.py", "--help"),
    ]
    for command in commands:
        result = _run(*command)
        assert result.returncode == 0, result.stderr
        assert "usage" in (result.stdout + result.stderr).lower()
