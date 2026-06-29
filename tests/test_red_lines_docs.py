"""Regression tests for narrow red-line boundaries."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_red_lines_are_narrow_damage_boundaries():
    text = _read("rules/red-lines.md")

    assert "## 红线最小化原则" in text
    assert "只读验证、低频单请求、浏览器观察、源码/JS 分析、CVE 情报" in text
    assert "OAST 回调、受控口令测试、反射/DOM XSS 低风险验证" in text
    assert "默认都不是红线" in text
    assert "状态改变方法不是天然红线" in text
    assert "不要因为“看起来敏感”而阻断 AI 的正常测试路线" in text
    assert "不是要求必须等其它高价值路线全部失败" in text
    assert "常规高价值路线已经产生稳定" not in text


def test_red_lines_block_destructive_methods_and_active_stored_xss():
    text = _read("rules/red-lines.md")
    flat = " ".join(text.split())

    assert "DDoS、高压流量、资源耗尽或服务中断" in text
    assert "触发真实副作用" in text
    assert "对真实数据执行会落库的 `DELETE` / `PATCH` / `PUT`" in text
    assert "账号、权限、组织成员、配置和 CI/CD 是高价值攻击面，不是天然高风险" in flat
    assert "风险来自具体动作效果" in text
    assert "Secret / API key 不是红线" in text
    assert "泄露密钥本身也不自动等于高价值漏洞" in text
    assert "对 secret 的处理属于漏洞 triage / validation，不属于红线风险评估" in text
    assert "不要为了“证明泄露风险”而停" in text
    assert "只读查看" in text
    assert "dry-run" in text
    assert "preview" in text
    assert "validate-only" in text
    assert "默认不主动测试存储型 XSS" in text
    assert "不得主动向评论、资料、工单、消息、富文本" in text
    assert "提交可执行 stored XSS payload" in text


def test_check_redlines_command_is_not_a_broad_permission_gate():
    text = _read("commands/check-redlines.md")

    assert "伤害目标系统、真实数据或真实用户" in text
    assert "红线检查是窄边界安全检查，不是泛化权限闸门" in text
    assert "改变真实账号/权限/CI/CD 状态的副作用" in text
    assert "Stored-XSS persistence risk" in text
    assert "Low-risk alternative" in text
    assert "没有安全替代方案且缺少当前回合明确 opt-in" in text


def test_autopilot_and_runtime_keep_red_lines_minimal():
    runtime = _read("skills/runtime-protocol.md")
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    assert "窄红线" in runtime
    assert "低频只读验证" in runtime
    assert "向目标系统持久化位置提交可执行 stored XSS payload" in runtime
    assert "会触发真实 CI/CD、生产部署、资源改写或生产配置变更的动作" in runtime
    assert "secret 外传" not in runtime

    for text in (command, agent):
        flat = " ".join(text.split())

        assert "Red-line checks are narrow safety checks, not broad" in flat
        assert "active stored XSS payload" in flat
        assert "Controlled credential testing" in flat or "Password brute force" in flat
        assert "not red lines" in flat or "absolute red lines" in flat

    command_flat = " ".join(command.split())
    assert "not a requirement that every other lane fails first" in command_flat
    assert "change real account or permission state" in command_flat
    assert "trigger CI/CD/deployment side effects" in command_flat
    assert "Other high-value lanes are blocked" not in command
