"""已知组件版本情报分支的文档契约回归测试。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_autopilot_requires_known_software_intelligence_lane():
    text = _read("docs/autopilot-lanes.md")
    intel = _read("commands/intel.md")

    assert "Known software" in text
    assert "tools/intel_engine.py" in text
    assert "select a reachable advisory" in text
    assert "collect_web_intel" in intel
    assert "test_advisory_applicability" in intel
    assert "tools/web_intel_artifact.py" in intel
    assert "action_queue" in intel


def test_web_intel_selects_search_provider_on_demand():
    claude = _read("CLAUDE.md")
    rule = _read("rules/web-intel.md")
    command = _read("commands/intel.md")

    assert "Grok Search 或 Smartsearch" in claude
    assert "不默认双重搜索" in rule
    assert "do not call both unless" in command


def test_autopilot_agent_inherits_known_software_lane():
    text = _read("agents/autopilot.md")
    flat = " ".join(text.split())

    assert "## Actionable Evidence Continuation" in text
    assert "Do not turn concrete evidence into a passive TODO" in text
    assert "tools/action_queue.py ingest-checkpoint --target <target>" in text
    assert "tools/action_queue.py resolve" in text
    assert "Do not end a run merely because a primary lane is blocked." in text
    assert "remaining high-value lanes have been executed, blocked, dead-end, or clearly not applicable" in text
    assert "Examples include auth bootstrap (register, invite, reset, verification)" in text
    assert "applies broadly: known software versions, exposed routes" in text
    assert "## Known Software Intelligence Lane" in text
    assert "concrete product/plugin/theme/library and version" in flat
    assert "Query CVE/advisory sources" in text
    assert 'do not leave "needs CVE lookup" as a final state.' in text
    assert "identified network services follow the same lane" in text.lower()
    assert "collect_web_intel" in text
    assert "test_advisory_applicability" in text


def test_wordpress_wpscan_is_explicitly_on_demand_and_bounded():
    command = _read("docs/autopilot-lanes.md")
    agent = _read("agents/autopilot.md")
    card = _read("knowledge/cards/wordpress-surface-intelligence.md")

    assert "knowledge/cards/wordpress-surface-intelligence.md" in command
    for text in (agent, card):
        assert "WPSCAN_API_TOKEN" in text
        assert "--enumerate p,t" in text
        assert "--no-update" in text
    assert "not default Recon" in agent
    assert "--password-attack" not in command
    assert "WPScan 命中、文件存在或 HTTP 200 不证明" in card


def test_coverage_gate_blocks_unresolved_component_versions():
    text = _read("rules/coverage-gate.md")

    assert "## 通用续跑 Gate" in text
    assert "不算覆盖完成" in text
    assert "tools/action_queue.py summary --target <target>" in text
    assert "适用范围不限于某个漏洞类别或某种技术栈" in text
    assert "已识别的产品、CMS、插件、主题、框架、库及其版本" in text
    assert "只记录“版本较新/\n  需要查 CVE”不算覆盖" in text
    assert "受影响版本判断、可达路径判断" in text


def test_tool_index_routes_component_versions_to_intel_tools():
    text = _read("docs/tool-index.md")

    assert "Concrete signal plus unresolved next verification question" in text
    assert "`tools/action_queue.py`" in text
    assert "Concrete CMS/plugin/theme/library version observed" in text
    assert "`/intel` → `tools/intel_engine.py`; add `/scan-cves` only after AI selects a reachable advisory" in text
