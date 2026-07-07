"""已知组件版本情报分支的文档契约回归测试。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_autopilot_requires_known_software_intelligence_lane():
    text = _read("commands/autopilot.md")
    flat = " ".join(text.split())

    assert "## Actionable Evidence Continuation Contract" in text
    assert "must not turn an evidence-backed next step into a passive TODO" in text
    assert "python3 tools/action_queue.py ingest-checkpoint --target target.com" in text
    assert "python3 tools/action_queue.py next --target target.com" in text
    assert "python3 tools/action_queue.py resolve --target target.com" in text
    assert "known product/CMS/plugin/theme/library versions" in text
    assert "authz/IDOR, SQLi/NoSQLi, SSRF, XXE, RCE/SSTI/command injection" in text
    assert "Do not overfit this contract into a fixed checklist" in text
    assert "When a primary lane is blocked, do not checkpoint/finish immediately if adjacent high-value lanes remain." in text
    assert "remaining high-value lanes are tested, blocked, dead-end, or not applicable" in text
    assert "## Known Software Intelligence Lane" in text
    assert 'must not stop at "needs CVE lookup."' in flat
    assert "one specialization of the Actionable Evidence Continuation Contract" in flat
    assert "python3 tools/intel_engine.py --target target.com" in text
    assert "python3 tools/cve_hunter.py target.com" in text
    assert "NVD, GitHub Advisory, WPScan/vulnerability DB" in text
    assert "vendor changelog" in text
    assert "WordPress Tribe Events 6.16.3" in text


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
    assert "`/intel`, `tools/intel_engine.py`, `tools/cve_hunter.py`, `/scan-cves`" in text
