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


def test_request_pair_rejects_undeclared_second_axis_for_query_and_path():
    """审计 F2：query:/path: 分支必须校验整份请求差异集合，不是只查 URL 内部。

    - query:id + Authorization 同时变化 -> 拒绝（差异归因要求单变量）
    - path:/x + body 同时变化 -> 拒绝
    - 重复 query key 的未声明首项变化 -> 拒绝（dict 折叠会掩盖）
    """
    import pytest
    from request_diff import RequestPairError, validate_request_pair

    dual_axis_query = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://t.test/rest/basket/1?id=2",
                             "headers": {"Authorization": "Bearer A"}},
        "variant_request": {"method": "GET", "url": "https://t.test/rest/basket/1?id=9",
                            "headers": {"Authorization": "Bearer B"}},
        "active_dimension": "query:id",
        "classifier": "authz",
        "vuln_class": "Authz",
    }
    with pytest.raises(RequestPairError, match="only request difference"):
        validate_request_pair(dual_axis_query)

    dual_axis_path = {
        "schema_version": 1,
        "baseline_request": {"method": "POST", "url": "https://t.test/api/x/1", "body": '{"a":1}'},
        "variant_request": {"method": "POST", "url": "https://t.test/api/x/2", "body": '{"a":2}'},
        "active_dimension": "path:x",
        "classifier": "authz",
        "vuln_class": "Authz",
    }
    with pytest.raises(RequestPairError, match="only request difference"):
        validate_request_pair(dual_axis_path)

    repeated_key_hidden = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://t.test/search?a=1&a=2&b=3"},
        "variant_request": {"method": "GET", "url": "https://t.test/search?a=9&a=2&b=4"},
        "active_dimension": "query:b",
        "classifier": "authz",
        "vuln_class": "Authz",
    }
    with pytest.raises(RequestPairError, match="only URL difference"):
        validate_request_pair(repeated_key_hidden)

    # 声明了重复 key 的变化（改的是重复组的首项且声明该 key）仍可表达。
    repeated_key_declared = {
        "schema_version": 1,
        "baseline_request": {"method": "GET", "url": "https://t.test/search?a=1&a=2&b=3"},
        "variant_request": {"method": "GET", "url": "https://t.test/search?a=1&a=2&b=4"},
        "active_dimension": "query:b",
        "classifier": "authz",
        "vuln_class": "Authz",
    }
    normalized = validate_request_pair(repeated_key_declared)
    assert normalized["active_dimension"] == "query:b"
