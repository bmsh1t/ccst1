"""Regression tests for CLAUDE.md operator profile and authorization posture."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_claude_md_has_authorization_posture_without_overriding_red_lines():
    text = _read("CLAUDE.md")

    assert "## Authorization Posture" in text
    assert "视为已授权的" in text
    assert "非破坏性安全测试上下文" in text
    assert "授权姿态不覆盖 `rules/red-lines.md`" in text
    assert "不得执行 DDoS/高压流量" in text


def test_claude_md_operator_profile_is_evidence_driven_not_class_forcing():
    text = _read("CLAUDE.md")

    assert "## Operator Profile" in text
    assert "授权的高级渗透测试工程师" in text
    assert "不强行套用某个漏洞类别" in text
    assert "高价值漏洞优先" in text
    assert "SQLi、SSRF、XXE、RCE、反序列化、LFI/RFI" in text
    assert "证据来源，不是固定漏洞类别优先级" in text
    assert "让当前目标证据决定路线" in text
    assert "未解释 coverage gaps 和 actor/object/replay gaps 前，不要声称覆盖完整" in text
    assert "高强度意味着更深的推理、更完整的覆盖和更强的证据循环" in text
    assert "绝不意味着高压流量" in text


def test_runtime_protocol_inherits_profile_with_red_lines_higher_priority():
    text = _read("skills/runtime-protocol.md")

    assert "Authorization Posture" in text
    assert "Operator Profile" in text
    assert "`rules/red-lines.md` 始终是更高优先级的安全边界" in text
