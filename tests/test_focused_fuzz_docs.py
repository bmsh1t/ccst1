"""Focused FFUF 的 AI 决策与证据交接文档契约。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_web2_recon_separates_automatic_baseline_from_ai_focused_fuzz():
    skill = _read("skills/web2-recon/SKILL.md")
    command = _read("commands/recon.md")
    normalized = " ".join(skill.split()).lower()

    assert "baseline ffuf" in normalized
    assert "focused fuzz" in normalized
    assert "ai 显式选择" in normalized
    assert "baseline 零命中而自动转入 focused fuzz" in normalized
    assert "不得机械合并整份通用大字典" in normalized
    assert "## Focused FFUF Discovery" in command
    assert "optional ai-selected discovery action" in " ".join(command.split()).lower()


def test_web2_recon_preserves_focused_ffuf_execution_capabilities():
    text = _read("commands/recon.md")

    for marker in (
        "ffuf -u 'https://target.com/FUZZ'",
        "ffuf -u 'https://target.com/api/v2/FUZZ'",
        'ffuf -request "$RUN_DIR/request.txt"',
        "-H 'Authorization: Bearer <token>'",
        "-b 'session=<cookie>'",
        "items?view=FUZZ",
        "-d '{\"action\":\"FUZZ\"}'",
        "-H 'X-API-Version: FUZZ'",
        "-mc all -ac",
        "-fc 404",
        "-fs <control-size>",
    ):
        assert marker in text

    assert "/tmp/ffuf-dirs.json" not in text
    assert "~/wordlists/api-endpoints.txt" not in text
    assert "seq 1 10000" not in text
    assert "-rate" not in text


def test_web2_recon_skill_stays_a_decision_layer():
    skill = _read("skills/web2-recon/SKILL.md")

    for removed in (
        "## STANDARD RECON PIPELINE",
        "## 30-MINUTE RECON PROTOCOL",
        "### Stack → Primary Bug Class Map",
        "### Pre-Hunt: Always Run First",
    ):
        assert removed not in skill
    assert "Branches are alternatives, not a mandatory order" in skill
    assert "Elapsed time alone never closes Recon" in skill
    assert "commands/recon.md" in skill


def test_web2_recon_uses_existing_isolated_artifact_and_memory_contracts():
    text = _read("commands/recon.md")
    normalized = " ".join(text.split())

    for marker in (
        "recon/<target_key>/focused_fuzz/",
        "wordlist.txt",
        "ffuf_results.jsonl.gz",
        "ffuf_summary.json",
        "tools/recon_adapter.py",
        "--summarize-ffuf",
        "--read-ffuf --offset 0 --limit 100",
        "tools/target_memory.py lead",
        "tools/target_memory.py dead-end",
        "keep the run out of `urls/all.txt`, Surface, Queue, Coverage, and Finding state",
    ):
        assert marker in normalized


def test_autopilot_entries_keep_focused_fuzz_ai_selected_and_non_automatic():
    command = " ".join(
        (_read("commands/autopilot.md") + _read("docs/autopilot-lanes.md")).split()
    ).lower()
    agent = " ".join(_read("agents/autopilot.md").split()).lower()
    skill = " ".join(_read("skills/web2-recon/SKILL.md").split()).lower()

    assert "focused fuzz" in command
    assert "optional ai-selected discovery actions" in command
    assert "skills/web2-recon/skill.md" in command
    for marker in (
        "one concrete template and bounded, deduplicated wordlist",
        "an empty baseline does not trigger focused fuzz",
        "recon/<target_key>/focused_fuzz/<run_id>/",
        "target_memory.py lead/dead-end",
        "never auto-expand surface, queue, or coverage",
        "same-target seeds expose a naming dialect",
        "random-miss response groups",
        "next bounded round",
        "route existence remains a signal, not a vulnerability candidate",
    ):
        assert marker in agent
    for marker in (
        "baseline ffuf",
        "focused fuzz",
        "ai 显式选择",
        "recon/<target_key>/focused_fuzz/",
        "target_memory.py lead",
    ):
        assert marker in skill


def test_target_dialect_is_evidence_linked_bounded_and_feedback_driven():
    skill = _read("skills/web2-recon/SKILL.md")
    command = _read("commands/recon.md")
    card = _read("knowledge/cards/path-pattern-management-exposure.md")
    combined = skill + "\n" + command + "\n" + card
    normalized_skill = " ".join(skill.split())

    for marker in (
        "seed_refs",
        "transformation",
        "rationale",
        "auth_context",
        "naming_profile.json",
        "candidates.jsonl",
        "随机 miss",
        "405/`Allow`",
        "SPA/soft-404",
        "登录跳转",
        "WAF",
        "不设置全局轮数上限",
    ):
        assert marker in combined

    assert "模型自报数字置信度" in combined
    assert "路由差异只形成 Signal" in skill
    assert "不拥有 finding、Surface、queue、coverage 或 target-memory 状态" in normalized_skill
