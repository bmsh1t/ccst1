"""Regression tests for narrow red-line boundaries."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_red_lines_are_narrow_damage_boundaries():
    text = _read("rules/red-lines.md")

    assert "## 红线最小化原则" in text
    assert "红线只拦截会伤害目标系统、真实用户或真实业务状态的动作" in text
    assert "状态改变方法不是天然红线" in text
    assert "不要因为“看起来敏感”而阻断 AI 的正常测试路线" in text
    assert "allow-with-controls" in text
    assert "常规高价值路线已经产生稳定" not in text


def test_red_lines_block_destructive_methods_and_active_stored_xss():
    text = _read("rules/red-lines.md")
    flat = " ".join(text.split())

    assert "DDoS、高压流量、资源耗尽或服务中断" in text
    assert "会不会修改、删除、篡改、污染真实数据/配置/业务状态？" in text
    assert "或触发真实副作用" not in text
    assert "对真实数据执行会落库的 `DELETE` / `PATCH` / `PUT`" in text
    assert "账号、权限、组织成员、配置和 CI/CD 是高价值攻击面，不是天然高风险" in flat
    assert "风险来自具体" in text
    assert "动作效果" in text
    assert "自动流程不得直接执行 `PUT`、`PATCH`、`DELETE` 或实际文件上传" in text
    assert "OTP/SAML 协议验证和 OAST 等仍按实际副作用判断，不做全局禁用" in text
    assert "技术名称、凭证来源和 HTTP method 都不是红线判断维度" in text
    assert "口令爆破、password spray、" in text
    assert "泄露密钥实际使用、认证/角色差异和协议测试默认可执行" in text
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
    assert "具体边界和四级决策只读取 `rules/red-lines.md`" in text
    assert "redline_required" in text
    assert "Stored-XSS persistence risk" in text
    assert "Low-risk alternative" in text
    assert "Controls: 频率、测试资源、停止条件、回滚或清理方式" in text
    assert "## 决策规则" not in text


def test_autopilot_and_runtime_keep_red_lines_minimal():
    runtime = _read("skills/runtime-protocol.md")
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    assert "窄红线" in runtime
    assert "唯一规则源" in runtime
    assert "检查层不复制红线类别、决策表或领域执行卫生" in runtime
    assert "PUT/PATCH/DELETE 的默认自动" in runtime
    assert "Credential、stored XSS" in runtime
    assert "secret 外传" not in runtime

    for text in (command, agent):
        flat = " ".join(text.split())

        assert "Red-line checks are narrow side-effect checks, not authorization or ownership gates" in flat
        assert "active stored XSS payload" in flat
        assert "Controlled credential testing" in flat or "Password brute force" in flat
        assert "not red lines" in flat or "absolute red lines" in flat

    command_flat = " ".join(command.split())
    assert "absolute red lines or a mandatory last lane" in command_flat
    assert "change real account or permission state" in command_flat
    assert "trigger CI/CD/deployment side effects" in command_flat
    assert "Other high-value lanes are blocked" not in command
