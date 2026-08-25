"""Regression tests for CLAUDE.md operator profile and authorization posture."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_claude_md_defines_authorized_context_and_side_effect_boundary():
    text = _read("CLAUDE.md")

    assert "## Authorization and Action Safety" in text
    assert "视为已授权的" in text
    assert "安全测试上下文" in text
    assert "allow-with-controls" in text
    assert "不要确认目标性质、公开/私有、归属或授权" in text


def test_claude_md_operator_profile_is_evidence_driven_not_class_forcing():
    text = _read("CLAUDE.md")
    flat = " ".join(text.split())

    assert "## Operator Contract" in text
    assert "授权的高级渗透测试工程师" in text
    assert "不强行套用漏洞类别" in text
    assert "高价值优先" in text
    assert "不得因模型默认偏好预先排除任何漏洞类别" in text
    assert "当前路线由目标证据、实际影响" in text
    assert "Action Queue 和有理由的覆盖缺口共同决定" in text
    assert "证据来源， 不是固定漏洞类别优先级" in flat
    assert "让证据决定路线" in text
    assert "actor/object/replay gap 时不得宣称覆盖完整" in text
    assert "高强度只表示更深推理、更完整覆盖和更强证据循环" in text
    assert "不表示高压流量" in text


def test_claude_md_keeps_specialist_ownership_in_the_current_session():
    text = _read("CLAUDE.md")
    normalized = " ".join(text.split())

    assert "Specialist 委派遵循 `commands/autopilot.md`" in text
    assert "当前 session 始终是唯一 controller" in normalized
    assert "结果回收、Checkpoint、owner 写回和 Closure" in normalized


def test_resin_defaults_to_sticky_without_proxying_local_targets():
    claude = _read("CLAUDE.md")
    command = _read("commands/autopilot.md")
    guide = _read("docs/resin-proxy.md")
    flat = " ".join(claude.split())

    assert "默认使用每个 target/job 稳定的 **sticky** Account" in flat
    assert "只有用户明确要求轮换出口时使用 **rotate**" in claude
    assert "localhost、RFC1918 和其他私网目标始终 **bypass** Resin" in flat
    assert "默认 mode 是 **sticky**" in guide
    assert "rotate 只在用户显式要求时使用" in guide
    assert "localhost / 内网 / RFC1918 始终 bypass" in guide
    assert "use current evidence and the request budget to decide" in command
    assert "不设固定上限" in guide


def test_runtime_protocol_inherits_profile_and_red_lines():
    text = _read("skills/runtime-protocol.md")

    assert "本协议只定义共享路由" in text
    assert "不重复加载或改写平台常驻契约" in text
