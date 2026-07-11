"""Claude CLI observation inventory wiring 契约。"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_observations_slash_command_is_neutral_and_bounded():
    text = _read("commands/observations.md")

    assert "observation_inventory.py sync" in text
    assert "observation_inventory.py summary" in text
    assert "--status untouched --limit 50" in text
    assert "untouched|reviewing|reviewed|parked" in text
    assert "不判断漏洞类别、攻击价值或下一项 Skill" in text
    assert "禁止根据列表顺序自动选择漏洞路线" in text


def test_autopilot_command_and_agent_consume_summary_without_auto_routing():
    command = _read("commands/autopilot.md")
    agent = _read("agents/autopilot.md")

    assert "observation_inventory.py summary" in command
    assert "/observations" in command
    assert "Never route every untouched observation to a Skill" in command
    assert "observation_inventory" in agent
    assert "Never auto-route or enqueue the full inventory" in agent


def test_tool_index_exposes_observation_inventory():
    text = _read("docs/tool-index.md")

    assert "tools/observation_inventory.py" in text
    assert "Persist neutral untouched/stale observations" in text
