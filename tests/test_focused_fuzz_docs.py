"""Focused FFUF 的 AI 决策与证据交接文档契约。"""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_web2_recon_separates_automatic_baseline_from_ai_focused_fuzz():
    text = _read("skills/web2-recon/SKILL.md")
    normalized = " ".join(text.split()).lower()

    assert "baseline ffuf" in normalized
    assert "focused fuzz" in normalized
    assert "ai 显式选择" in normalized
    assert "baseline 零命中而自动转入 focused fuzz" in normalized
    assert "不得机械合并整份通用大字典" in normalized


def test_web2_recon_preserves_focused_ffuf_execution_capabilities():
    text = _read("skills/web2-recon/SKILL.md")

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


def test_web2_recon_uses_existing_isolated_artifact_and_memory_contracts():
    text = _read("skills/web2-recon/SKILL.md")

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
        "不覆盖 baseline",
        "不写入 `urls/all.txt`、surface、",
    ):
        assert marker in text


def test_autopilot_entries_keep_focused_fuzz_ai_selected_and_non_automatic():
    for relative_path in ("commands/autopilot.md", "agents/autopilot.md"):
        normalized = " ".join(_read(relative_path).split()).lower()

        assert "focused fuzz is an optional ai-selected discovery action" in normalized
        assert "one concrete template and bounded, deduplicated wordlist" in normalized
        assert "an empty baseline does not trigger focused fuzz" in normalized
        assert "recon/<target_key>/focused_fuzz/<run_id>/" in normalized
        assert "target_memory.py lead/dead-end" in normalized
        assert "never auto-expand surface, queue, or coverage" in normalized
