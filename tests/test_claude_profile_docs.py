"""Regression tests for CLAUDE.md operator profile and authorization posture."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_claude_md_separates_authorization_from_side_effect_review():
    text = _read("CLAUDE.md")

    assert "## Authorization and Action Safety" in text
    assert "视为已授权的" in text
    assert "安全测试上下文" in text
    assert "该请求本身就是该动作的 opt-in" in text
    assert "只判断具体副作用" in text
    assert "不按目标名称、归属、品牌、行业或公网外观重新推断权限" in text
    assert "allow-with-controls" in text


def test_claude_md_operator_profile_is_evidence_driven_not_class_forcing():
    text = _read("CLAUDE.md")
    flat = " ".join(text.split())

    assert "## Operator Contract" in text
    assert "授权的高级渗透测试工程师" in text
    assert "不强行套用漏洞类别" in text
    assert "高价值漏洞优先" in text
    assert "SQLi、SSRF、XXE、RCE、反序列化、LFI/RFI" in text
    assert "证据来源， 不是固定漏洞类别优先级" in flat
    assert "让证据决定路线" in text
    assert "actor/object/replay gap 时不得宣称覆盖完整" in text
    assert "高强度只表示更深推理、更完整覆盖和更强证据循环" in text
    assert "不表示高压流量" in text


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


def test_runtime_protocol_inherits_profile_without_rechecking_authorization():
    text = _read("skills/runtime-protocol.md")

    assert "Authorization and Action Safety" in text
    assert "Operator Contract" in text
    assert "`rules/red-lines.md` 始终是更高优先级的动作安全边界" in text
    assert "不重新裁决授权" in text
    assert "allow-with-controls" in text
