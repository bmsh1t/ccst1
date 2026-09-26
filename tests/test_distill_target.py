"""distill_target: AI-direct-write distillation contracts (post-2026-09-13 audit).

旧的 prompt/commit 三元组中转已退役；本文件锁住新契约：
- evidence 视图是唯一机器步骤（拉 ledger/findings/case_state 出有界视图）
- 旧 CLI 子命令（prompt/commit）不再存在
- 机械保护（脱敏、target-owned refs）活在 knowledge_audit 晋升门
  （见 tests/test_knowledge_audit.py 的对应覆盖）
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from tools.target_store import TargetStore
from tools.distill_target import _bounded_evidence_view, build_evidence_view, build_parser


def _seed_target(repo: Path, target: str) -> None:
    store = TargetStore(repo, target)
    store.initialize()
    probe = repo / "evidence" / target / "probe" / "probe-1.json"
    probe.parent.mkdir(parents=True)
    probe.write_text(json.dumps({"request": "GET /rest/basket/1", "response": "403 Forbidden"}))
    store.start_attempt(attempt_id="probe-1", source="native", started_at="2026-09-24T00:00:00Z", actor="test")
    store.record_execution(attempt_id="probe-1", outcome="complete", actor="test", observations=[{
        "endpoint": f"https://{target}/rest/basket/1", "method": "GET", "family": "IDOR",
        "observed_at": "2026-09-24T00:00:00Z", "description": "Peer denied",
        "artifacts": {"response": probe.relative_to(repo).as_posix()}, "state_changing": False,
    }])


def test_evidence_view_pulls_store_observations_and_points_to_direct_write(tmp_path):
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


def test_evidence_view_distinguishes_empty_store_from_uninitialized(tmp_path):
    with pytest.raises(ValueError, match="not initialized"):
        build_evidence_view(tmp_path, "never-seen.example")
    assert not (tmp_path / "state").exists()
    TargetStore(tmp_path, "never-seen.example").initialize()
    result = build_evidence_view(tmp_path, "never-seen.example")
    assert result["evidence_counts"]["ledger"] == 0
    assert result["evidence_counts"]["findings"] == 0
    assert result["evidence_counts"]["experiences"] == 0
    assert result["windows"]["experiences"]["total"] == 0
    assert "--repo-root" in result["view"]


def test_distillation_keeps_identifiers_and_marks_claim_excerpt():
    finding_id = "finding-" + "a" * 80
    endpoint = "https://t.example/" + "segment/" * 30
    event_id = "operation-" + "b" * 80
    view = _bounded_evidence_view({
        "ledger": [{"event_id": event_id}],
        "findings": [{"id": finding_id, "endpoint": endpoint, "claim": "x" * 500}],
        "case_state": {},
    })
    assert finding_id in view and event_id in view and endpoint in view
    assert "160 字预览" in view and "x" * 161 not in view


def test_primary_distillation_preserves_finding_judgment_and_experience_conditions(tmp_path):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "t.example")
    store.initialize()
    store.create_finding(
        command_id="finding-1", finding_id="f1", endpoint="https://t.example/api/x",
        method="GET", family="idor", title="Peer object", claim="Peer object may be readable",
        actor="operator",
    )
    response = tmp_path / ".private" / "validation" / "t.example" / "response.txt"
    response.parent.mkdir(parents=True)
    response.write_text("HTTP/1.1 403 Forbidden\r\n\r\n")
    store.start_attempt(attempt_id="attempt-1", source="native", started_at="2026-09-23T00:00:00Z",
                        actor="operator")
    operation = store.record_execution(
        attempt_id="attempt-1", outcome="complete", actor="operator",
        observations=[{"endpoint": "https://t.example/api/x", "method": "GET", "family": "idor",
                       "observed_at": "2026-09-23T00:00:00Z", "description": "Peer read denied",
                       "artifacts": {"response": response.relative_to(tmp_path).as_posix()},
                       "state_changing": False}],
        candidate={"id": "f1", "endpoint": "https://t.example/api/x", "method": "GET",
                   "family": "idor", "title": "Peer object", "claim": "Peer object may be readable"},
    )
    store.assess(
        command_id="assessment-1", finding_id="f1", verdict="inconclusive",
        reason="Peer session expired", boundary="Cross-actor object read", impact="",
        evidence=[{"operation_id": operation["entity_id"], "step": 0}],
        actor="operator", expected_assessment=None,
    )
    store.decide_delivery(
        command_id="delivery-1", finding_id="f1", assessment_id="assessment-1",
        destination="internal-review", status="ineligible", reason="Needs a live peer session",
        actor="operator", expected_decision=None,
    )
    for index in range(12):
        store.remember(command_id=f"note-{index}", kind="note", statement=f"Candidate {index}",
                       conditions="same tenant", reopen_when="new peer session",
                       next_intent="compare response", evidence=[], actor="operator")

    result = build_evidence_view(tmp_path, "t.example")
    view = result["view"]
    assert "f1 [IDOR] Peer object may be readable technical=inconclusive endpoint=https://t.example/api/x" in view
    assert "reason=Peer session expired boundary=Cross-actor object read" in view
    assert "delivery=internal-review:ineligible stale=False" in view
    assert "note-11 [note] Candidate 11" in view
    assert "conditions=same tenant reopen_when=new peer session next_intent=compare response" in view
    assert "--target t.example --id EXPERIENCE_ID" in view
    assert result["evidence_counts"]["findings"] == 1
    assert result["evidence_counts"]["experiences"] == 12
    assert result["windows"]["experiences"]["remaining"] == 2
    assert result["windows"]["experiences"]["next_cursor"]


def test_retired_intermediate_api_is_gone():
    """旧出题/三元组中转不得回归（原生能力审计 2026-09-13 第 3 步）。"""
    import tools.distill_target as dt

    for name in ("build_prompt", "commit_triple", "_scrub_triple",
                 "_validate_evidence_refs", "render_candidate_card", "TYPOLOGIES"):
        assert not hasattr(dt, name), name


def test_cli_only_supports_evidence_subcommand(tmp_path, capsys):
    from tools.distill_target import main

    _seed_target(tmp_path, "t.example")
    rc = main(["--repo-root", str(tmp_path), "evidence", "--target", "t.example", "--json"])
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


def test_primary_distill_cli_emits_executable_root_bound_expansions(tmp_path):
    from tools.target_store import TargetStore

    repo = Path(__file__).resolve().parents[1]
    root = tmp_path / "isolated root"
    target = "distill-cli.test"
    store = TargetStore(root, target)
    store.initialize()
    for index in range(12):
        store.create_finding(command_id=f"create-{index}", finding_id=f"F-{index:02}",
                             endpoint=f"https://{target}/objects/{index}", method="GET",
                             family="custom-object-boundary", title="Object claim", claim=f"Claim {index}",
                             actor="operator")
        store.remember(command_id=f"note-{index:02}", kind="note", statement=f"Premise {index}",
                       conditions="same tenant", reopen_when="new peer session", next_intent="compare",
                       evidence=[], actor="operator")
    store.upsert_case_actor(command_id="actor", actor_id="peer", role="user", label="Peer", actor="operator")
    before = store.binding()
    result = subprocess.run([
        sys.executable, "-B", str(repo / "tools/distill_target.py"),
        "--repo-root", str(root), "evidence", "--target", target,
    ], capture_output=True, text=True, check=True)
    view = json.loads(result.stdout)
    for source, key, first_id, tail_ids in (
        ("findings", "items", "F-00", ["F-10", "F-11"]),
        ("experiences", "target_entries", "note-11", ["note-01", "note-00"]),
    ):
        window = view["windows"][source]
        assert window["remaining"] == 2
        assert window["next_command"] in view["view"]
        next_page = subprocess.run(shlex.split(window["next_command"]), cwd=repo,
                                   capture_output=True, text=True, check=True)
        records = json.loads(next_page.stdout)[key]
        assert [row.get("id") or row["entry_id"] for row in records] == tail_ids
        command = shlex.split(window["expand_command"])
        command[-1] = first_id
        expanded = subprocess.run(command, cwd=repo, capture_output=True, text=True, check=True)
        payload = json.loads(expanded.stdout)
        if source == "findings":
            assert payload["id"] == first_id and payload["claim"] == "Claim 0"
        else:
            assert payload["target_entries"][0]["conditions"] == "same tenant"
    case = subprocess.run(shlex.split(view["case_expand_command"]), cwd=repo,
                           capture_output=True, text=True, check=True)
    assert json.loads(case.stdout)["actors"]["peer"]["label"] == "Peer"
    assert "recorded_by=operator" in view["view"]
    assert store.binding() == before
    assert not (root / "findings" / target / "findings.json").exists()

    store.remember(command_id="new-revision", kind="note", statement="Later context",
                   conditions="unknown", reopen_when="", next_intent="", evidence=[], actor="operator")
    stale = subprocess.run(shlex.split(view["windows"]["findings"]["next_command"]), cwd=repo,
                            capture_output=True, text=True)
    assert stale.returncode == 2 and "snapshot changed" in stale.stderr
    missing_root = tmp_path / "uninitialized"
    for command in ("findings", "case"):
        missing = subprocess.run([sys.executable, "-B", str(repo / "tools/target_store.py"), command,
                                  "--repo-root", str(missing_root), "--target", target],
                                 capture_output=True, text=True)
        assert missing.returncode == 2 and "not initialized" in missing.stderr
    assert not missing_root.exists()
