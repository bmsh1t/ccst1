"""distill_target: AI-direct-write distillation contracts (post-2026-09-13 audit).

旧的 prompt/commit 三元组中转已退役；本文件锁住新契约：
- evidence 视图是唯一机器步骤（拉 ledger/findings/case_state 出有界视图）
- 旧 CLI 子命令（prompt/commit）不再存在
- 机械保护（脱敏、target-owned refs）活在 knowledge_audit 晋升门
  （见 tests/test_knowledge_audit.py 的对应覆盖）
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.distill_target import build_evidence_view, build_parser


def _seed_target(repo: Path, target: str) -> None:
    key = target.replace(":", "-")
    evidence_dir = repo / "evidence" / key / "probe"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    probe = evidence_dir / "probe-1.json"
    probe.write_text(json.dumps({"kind": "probe"}), encoding="utf-8")
    ledger_dir = repo / "memory" / "evidence" / key
    ledger_dir.mkdir(parents=True, exist_ok=True)
    (ledger_dir / "ledger.jsonl").write_text(
        json.dumps(
            {
                "event_id": "probe-1",
                "endpoint": "/rest/basket/1",
                "method": "GET",
                "vuln_class": "IDOR",
                "actor": "peer",
                "variant": "id_swap",
                "result": "lead",
                "evidence_ref": f"evidence/{key}/probe/probe-1.json",
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def test_evidence_view_pulls_ledger_and_points_to_direct_write(tmp_path):
    _seed_target(tmp_path, "t.example")
    result = build_evidence_view(tmp_path, "t.example")

    assert result["schema_version"] == 2
    assert result["evidence_counts"]["ledger"] == 1
    assert "/rest/basket/1" in result["view"]
    assert "evidence/t.example/probe/probe-1.json" in result["view"]
    # next 指向直写契约（不再有 triple/commit 中转）
    assert "knowledge/candidates/" in result["next"]
    assert "card-template" in result["next"]
    assert "knowledge_promote" in result["next"]
    assert "triple" not in result["next"]


def test_evidence_view_degrades_without_evidence(tmp_path):
    result = build_evidence_view(tmp_path, "never-seen.example")
    assert result["evidence_counts"]["ledger"] == 0
    assert result["view"] == "(no target-owned evidence found)"


def test_retired_intermediate_api_is_gone():
    """旧出题/三元组中转不得回归（原生能力审计 2026-09-13 第 3 步）。"""
    import tools.distill_target as dt

    for name in ("build_prompt", "commit_triple", "_scrub_triple",
                 "_validate_evidence_refs", "render_candidate_card", "TYPOLOGIES"):
        assert not hasattr(dt, name), name


def test_cli_only_supports_evidence_subcommand(tmp_path, capsys):
    from tools.distill_target import main

    _seed_target(tmp_path, "t.example")
    rc = main(["evidence", "--target", "t.example", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 2

    # 旧子命令必须被 argparse 拒绝
    with pytest.raises(SystemExit) as exc:
        main(["prompt", "--target", "t.example"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["commit", "--target", "t.example", "--triple-json", "{}"])
    assert exc.value.code == 2
