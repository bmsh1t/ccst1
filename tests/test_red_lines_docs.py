"""Regression tests for narrow red-line boundaries."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_red_lines_are_narrow_damage_boundaries():
    text = _read("rules/red-lines.md")
    flat = " ".join(text.split())

    assert "唯一原则：不要执行会伤害目标系统、真实用户或真实业务状态的破坏性动作" in text
    assert "漏洞类别、CVE/PoC、产品、凭证来源、HTTP method" in text
    assert "`exploit`、`payload` 和版本不确定性都不是红线理由" in text
    assert "三项均为 no 时直接 `allow`" in flat
    assert "allow-with-controls" in text
    assert "常规高价值路线已经产生稳定" not in text


def test_red_lines_block_destructive_methods_and_active_stored_xss():
    text = _read("rules/red-lines.md")

    assert "DDoS、高压流量、资源耗尽或服务中断" in text
    assert "不可控地修改、删除或污染真实数据、账号、权限、配置或业务状态" in text
    assert "写入会执行、持久化并影响真实用户的内容" in text
    assert "实际 `PUT`、`PATCH`、`DELETE` 或文件上传先进入 checkpoint" in text
    assert "这是人工复核门禁" in text
    assert "自动流程默认不提交可执行 stored XSS" in text
    assert "stored XSS" in text
    assert "测试资源" in text and "清理方式" in text and "当前回合明确 opt-in" in text


def test_bounded_non_destructive_checks_are_allowed():
    text = _read("rules/red-lines.md")

    assert "有界、低频且无破坏性副作用的检测默认允许" in text
    assert "`blocked: insufficient-evidence`，不是红线" in text


def test_manual_redline_wrapper_is_removed():
    assert not (REPO_ROOT / "commands" / "check-redlines.md").exists()
    assert "/check-redlines" not in _read("CLAUDE.md")
    assert "commands/check-redlines.md" not in _read("rules/red-lines.md")


def test_autopilot_and_runtime_keep_red_lines_minimal():
    runtime = _read("skills/runtime-protocol.md")
    command = _read("commands/autopilot.md")
    lanes = _read("docs/autopilot-lanes.md")
    agent = _read("agents/autopilot.md")

    assert "窄红线" in runtime
    assert "唯一规则源" in runtime
    assert "检查层不复制红线类别、决策表或领域执行卫生" in runtime
    assert "PUT/PATCH/DELETE 的默认自动" in runtime
    assert "Credential、stored XSS" in runtime
    assert "secret 外传" not in runtime

    command_flat = " ".join(f"{command}\n{lanes}".split())
    agent_flat = " ".join(agent.split())

    assert "Apply `rules/red-lines.md` to the concrete action" in command_flat
    assert "`rules/red-lines.md` classifies concrete side effects" in agent_flat
    assert "Deep mode follows `rules/red-lines.md` for action boundaries" in agent_flat
    assert "dry-run/preview/validate-only/inert" not in agent
    assert "not mandatory last lanes" in command_flat
    assert "Other high-value lanes are blocked" not in command
