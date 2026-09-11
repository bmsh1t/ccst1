"""候选 staging 与生命周期审计的行为测试。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from tools import knowledge_candidates as candidates
from tools import target_memory
from tools.experience_schema import make_entry_id
from tools.distill_reports import ingest_candidates
from tools.case_corpus import build_corpus
from tools.target_paths import target_storage_key


def _seed_target(repo: Path, target: str, *, evidence: str | None = "memory/evidence/example/ledger.jsonl") -> str:
    target_path = repo / "memory" / "goals" / "targets" / f"{target_storage_key(target)}.json"
    target_path.parent.mkdir(parents=True, exist_ok=True)
    refs = [evidence] if evidence else []
    entry_id = make_entry_id(
        target=target,
        field="useful_patterns",
        text=f"pattern for {target}",
        evidence_refs=refs,
    )
    target_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": target,
                "useful_patterns": [
                    {
                        "entry_id": entry_id,
                        "kind": "validation-technique",
                        "text": f"pattern for {target}",
                        "evidence_refs": refs,
                    }
                ],
                "dead_ends": [],
            }
        ),
        encoding="utf-8",
    )
    return entry_id


def _repo_with_evidence(tmp_path: Path) -> Path:
    evidence = tmp_path / "memory" / "evidence" / "example" / "ledger.jsonl"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"result":"tested_clean"}\n', encoding="utf-8")
    return tmp_path


def test_target_memory_experience_entry_has_id_kind_and_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(target_memory, "BASE_DIR", tmp_path)
    monkeypatch.setattr(target_memory, "GOALS_DIR", tmp_path / "memory" / "goals")
    monkeypatch.setattr(target_memory, "ACTIVE_PATH", tmp_path / "memory" / "goals" / "active.json")
    monkeypatch.setattr(target_memory, "TARGETS_DIR", tmp_path / "memory" / "goals" / "targets")
    monkeypatch.setattr(target_memory, "SESSIONS_DIR", tmp_path / "memory" / "goals" / "sessions")

    message = target_memory.append_entry(
        argparse.Namespace(
            target="example.com",
            text=["Use", "read-only", "role", "diff"],
            kind="validation-technique",
            evidence_ref=["memory/evidence/example/ledger.jsonl#L1"],
        ),
        "useful_patterns",
        "PATTERN",
    )
    saved = target_memory.load_target_memory("example.com")
    entry = saved["useful_patterns"][-1]
    assert entry["entry_id"].startswith("tm-")
    assert entry["kind"] == "validation-technique"
    assert entry["evidence_refs"] == ["memory/evidence/example/ledger.jsonl#L1"]
    assert entry["entry_id"] in message


def test_stage_candidate_requires_evidence_and_preserves_sources(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    entry_id = _seed_target(repo, "example.com")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"

    candidate_id, path = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="validation-technique",
        title="Role diff",
        summary="Compare one actor variable and preserve the response difference.",
        source_pairs=[["example.com", entry_id]],
    )
    assert candidate_id.startswith("cand-")
    assert path.is_file()
    states, errors = candidates._state_map(lifecycle)
    assert not errors
    assert states[candidate_id]["status"] == "pending"
    assert states[candidate_id]["evidence_refs"] == ["memory/evidence/example/ledger.jsonl"]
    assert states[candidate_id]["kind"] == "validation-technique"
    assert states[candidate_id]["title"] == "Role diff"
    assert states[candidate_id]["summary"].startswith("Compare one actor")
    assert "example.com" in path.read_text(encoding="utf-8")


def test_review_recall_signals_are_optional_normalized_and_safe(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    entry_id = _seed_target(repo, "example.com")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="validation-technique",
        title="Hidden binder",
        summary="Transfer a sibling parameter bundle before reducing fields.",
        source_pairs=[["example.com", entry_id]],
    )

    candidates._transition(
        candidate_id,
        action="reviewed",
        reviewer="human",
        reason="Reusable after review.",
        recall_signals=["hidden binder", "隐藏参数", "Hidden Binder"],
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    states, errors = candidates._state_map(lifecycle)

    assert not errors
    assert states[candidate_id]["recall_signals"] == ["hidden binder", "隐藏参数"]


@pytest.mark.parametrize(
    "signals,error",
    [
        (["example.com hidden binder"], "source target"),
        (["hidden binder", " "], "non-empty strings"),
        (["x" * 121], "at most 120"),
        (["A" * 32], "email or token"),
    ],
)
def test_review_rejects_unsafe_recall_signals_without_appending(
    tmp_path, signals, error
):
    repo = _repo_with_evidence(tmp_path)
    entry_id = _seed_target(repo, "example.com")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="useful-pattern",
        title="Safe projection",
        summary="Only reviewed, reusable text belongs in runtime hints.",
        source_pairs=[["example.com", entry_id]],
    )
    before = lifecycle.read_bytes()

    with pytest.raises(ValueError, match=error):
        candidates._transition(
            candidate_id,
            action="reviewed",
            reviewer="human",
            reason="Review attempt.",
            recall_signals=signals,
            repo_root=repo,
            lifecycle_path=lifecycle,
        )

    assert lifecycle.read_bytes() == before


def test_review_without_recall_signals_preserves_legacy_behavior(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    entry_id = _seed_target(repo, "example.com")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="useful-pattern",
        title="Manual only",
        summary="This reviewed candidate remains outside runtime recall.",
        source_pairs=[["example.com", entry_id]],
    )

    candidates._transition(
        candidate_id,
        action="reviewed",
        reviewer="human",
        reason="Keep manual-only compatibility.",
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    states, errors = candidates._state_map(lifecycle)

    assert not errors
    assert states[candidate_id]["status"] == "reviewed"
    assert "recall_signals" not in states[candidate_id]


def test_replay_rejects_recall_signals_on_staged_event(tmp_path):
    lifecycle = tmp_path / "knowledge" / "candidates" / "lifecycle.jsonl"
    event = candidates._event(
        candidate_id="cand-malformed",
        action="staged",
        from_status=None,
        to_status="pending",
        candidate_path="knowledge/candidates/cand-malformed.md",
        kind="useful-pattern",
        title="Malformed projection",
        summary="Staging cannot pre-authorize runtime recall.",
        recall_signals=["hidden binder"],
    )
    candidates._append_event(event, path=lifecycle)

    _, errors = candidates._state_map(lifecycle)

    assert errors


def test_replay_rejects_review_event_overwriting_staged_fields(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    entry_id = _seed_target(repo, "example.com")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="useful-pattern",
        title="Owner-bound projection",
        summary="Only staged owns display text and only review owns recall signals.",
        source_pairs=[["example.com", entry_id]],
    )
    event = candidates._event(
        candidate_id=candidate_id,
        action="reviewed",
        from_status="pending",
        to_status="reviewed",
        candidate_path=f"knowledge/candidates/{candidate_id}.md",
        reviewer="human",
        reason="Malformed fixture.",
    )
    event.update({"title": "Replacement title", "sources": []})
    candidates._append_event(event, path=lifecycle)

    _, errors = candidates._state_map(lifecycle)

    assert errors


def test_replay_rejects_non_normalized_corroboration_evidence(tmp_path):
    lifecycle = tmp_path / "knowledge" / "candidates" / "lifecycle.jsonl"
    staged = candidates._event(
        candidate_id="cand-malformed",
        action="staged",
        from_status=None,
        to_status="pending",
        candidate_path="knowledge/candidates/cand-malformed.md",
        sources=[
            {"type": "target-memory", "target": "one.example", "entry_id": "tm-one"}
        ],
        evidence_refs=["evidence/one.json"],
    )
    corroborated = candidates._event(
        candidate_id="cand-malformed",
        action="corroborated",
        from_status="pending",
        to_status="pending",
        candidate_path="knowledge/candidates/cand-malformed.md",
        sources=[
            {"type": "target-memory", "target": "two.example", "entry_id": "tm-two"}
        ],
        evidence_refs=["evidence/two.json"],
    )
    corroborated["evidence_refs"] = ["evidence/two.json", "evidence/two.json"]
    candidates._append_event(staged, path=lifecycle)
    candidates._append_event(corroborated, path=lifecycle)

    _, errors = candidates._state_map(lifecycle)

    assert errors


def test_stage_cross_target_candidate_records_two_sources(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    first = _seed_target(repo, "one.example")
    second = _seed_target(repo, "two.example")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="useful-pattern",
        title="Shared pattern",
        summary="The same low-risk validation path worked on both targets.",
        source_pairs=[["one.example", first], ["two.example", second]],
    )
    states, _ = candidates._state_map(lifecycle)
    assert {item["target"] for item in states[candidate_id]["sources"]} == {
        "one.example",
        "two.example",
    }


@pytest.mark.parametrize("reviewed", [False, True])
def test_corroborate_appends_independent_source_without_changing_status(
    tmp_path, reviewed
):
    repo = _repo_with_evidence(tmp_path)
    first = _seed_target(repo, "one.example")
    second = _seed_target(repo, "two.example")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="validation-technique",
        title="Cross-target replay",
        summary="Independent evidence can corroborate the same candidate.",
        source_pairs=[["one.example", first]],
    )
    if reviewed:
        candidates._transition(
            candidate_id,
            action="reviewed",
            reviewer="human",
            reason="Reviewed before corroboration.",
            recall_signals=["cross-target replay"],
            repo_root=repo,
            lifecycle_path=lifecycle,
        )

    candidates.corroborate(
        candidate_id,
        target="two.example",
        entry_id=second,
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    states, errors = candidates._state_map(lifecycle)

    assert not errors
    assert states[candidate_id]["status"] == ("reviewed" if reviewed else "pending")
    assert {item["target"] for item in states[candidate_id]["sources"]} == {
        "one.example",
        "two.example",
    }


def test_corroborate_rejects_duplicate_target_without_appending(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    first = _seed_target(repo, "one.example")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="useful-pattern",
        title="No duplicate target",
        summary="One target cannot corroborate itself with another entry.",
        source_pairs=[["one.example", first]],
    )
    before = lifecycle.read_bytes()

    with pytest.raises(ValueError, match="already has a source"):
        candidates.corroborate(
            candidate_id,
            target="https://one.example/path",
            entry_id=first,
            repo_root=repo,
            lifecycle_path=lifecycle,
        )

    assert lifecycle.read_bytes() == before


def test_corroborate_rejects_target_embedded_in_reviewed_signal_without_appending(
    tmp_path,
):
    repo = _repo_with_evidence(tmp_path)
    first = _seed_target(repo, "one.example")
    second = _seed_target(repo, "two.example")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="validation-technique",
        title="Signal/source isolation",
        summary="Later evidence sources cannot become routing signals.",
        source_pairs=[["one.example", first]],
    )
    candidates._transition(
        candidate_id,
        action="reviewed",
        reviewer="human",
        reason="Reviewed before the second source existed.",
        recall_signals=["two.example response marker"],
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    before = lifecycle.read_bytes()

    with pytest.raises(ValueError, match="conflicts with a recall signal"):
        candidates.corroborate(
            candidate_id,
            target="two.example",
            entry_id=second,
            repo_root=repo,
            lifecycle_path=lifecycle,
        )

    assert lifecycle.read_bytes() == before


def test_corroborate_rejects_source_without_evidence_without_appending(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    first = _seed_target(repo, "one.example")
    second = _seed_target(repo, "two.example", evidence=None)
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="validation-technique",
        title="Evidence-bound corroboration",
        summary="Every independent source needs a local evidence reference.",
        source_pairs=[["one.example", first]],
    )
    before = lifecycle.read_bytes()

    with pytest.raises(ValueError, match="no evidence_refs"):
        candidates.corroborate(
            candidate_id,
            target="two.example",
            entry_id=second,
            repo_root=repo,
            lifecycle_path=lifecycle,
        )

    assert lifecycle.read_bytes() == before


def test_corroborate_rejects_terminal_or_invalid_lifecycle_without_appending(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    first = _seed_target(repo, "one.example")
    second = _seed_target(repo, "two.example")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="dead-end",
        title="Terminal candidate",
        summary="Terminal candidates cannot receive corroboration.",
        source_pairs=[["one.example", first]],
    )
    candidates._transition(
        candidate_id,
        action="reviewed",
        reviewer="human",
        reason="Reviewed.",
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    candidates._transition(
        candidate_id,
        action="rejected",
        reviewer="human",
        reason="Not reusable.",
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    before = lifecycle.read_bytes()
    with pytest.raises(ValueError, match="not corroboratable"):
        candidates.corroborate(
            candidate_id,
            target="two.example",
            entry_id=second,
            repo_root=repo,
            lifecycle_path=lifecycle,
        )
    assert lifecycle.read_bytes() == before

    lifecycle.write_bytes(before + b"not-json\n")
    corrupt = lifecycle.read_bytes()
    with pytest.raises(ValueError, match="invalid lifecycle"):
        candidates.corroborate(
            candidate_id,
            target="two.example",
            entry_id=second,
            repo_root=repo,
            lifecycle_path=lifecycle,
        )
    assert lifecycle.read_bytes() == corrupt


def test_stage_invalid_source_does_not_create_candidate(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    entry_id = _seed_target(repo, "example.com", evidence=None)
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    with pytest.raises(ValueError, match="no evidence_refs"):
        candidates.stage_candidate(
            repo_root=repo,
            lifecycle_path=lifecycle,
            kind="dead-end",
            title="No proof",
            summary="This source is not ready.",
            source_pairs=[["example.com", entry_id]],
        )
    assert not lifecycle.exists()
    assert not list((repo / "knowledge" / "candidates").glob("cand-*.md"))


def test_lifecycle_rejects_transition_after_terminal(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    entry_id = _seed_target(repo, "example.com")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="useful-pattern",
        title="Terminal",
        summary="A candidate with a complete review path.",
        source_pairs=[["example.com", entry_id]],
    )
    candidates._transition(
        candidate_id,
        action="reviewed",
        reviewer="human",
        reason="Reviewed evidence.",
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    candidates._transition(
        candidate_id,
        action="rejected",
        reviewer="human",
        reason="Not transferable.",
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    with pytest.raises(ValueError, match="got rejected"):
        candidates._transition(
            candidate_id,
            action="reviewed",
            reviewer="human",
            reason="Duplicate review.",
            repo_root=repo,
            lifecycle_path=lifecycle,
        )
    result = candidates.audit_candidates(repo_root=repo, lifecycle_path=lifecycle, strict=True)
    assert result["ok"] is True
    assert result["statuses"]["rejected"] == 1


def test_promote_requires_registered_card_and_clean_audit(tmp_path, monkeypatch):
    repo = _repo_with_evidence(tmp_path)
    entry_id = _seed_target(repo, "example.com")
    lifecycle = repo / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo,
        lifecycle_path=lifecycle,
        kind="useful-pattern",
        title="Promotable",
        summary="A reviewed, reusable pattern.",
        source_pairs=[["example.com", entry_id]],
    )
    candidates._transition(
        candidate_id,
        action="reviewed",
        reviewer="human",
        reason="Two target review complete.",
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    card = repo / "knowledge" / "cards" / "promotable.md"
    card.parent.mkdir(parents=True, exist_ok=True)
    card.write_text("# Promotable\n", encoding="utf-8")

    class Registry:
        def card_paths(self):
            return {"promotable": "knowledge/cards/promotable.md"}

    class Report:
        errors = 0
        warnings = 0

    monkeypatch.setattr(candidates, "load_registry", lambda repo_root: Registry())
    monkeypatch.setattr(candidates, "audit_repository", lambda repo_root: Report())
    candidates._transition(
        candidate_id,
        action="promoted",
        reviewer="human",
        reason="Formal card passed the quality gate.",
        card_id="promotable",
        repo_root=repo,
        lifecycle_path=lifecycle,
    )
    result = candidates.audit_candidates(repo_root=repo, lifecycle_path=lifecycle, strict=True)
    assert result["ok"] is True
    assert result["statuses"]["promoted"] == 1


def test_distill_ingest_registers_corpus_source(tmp_path):
    repo = tmp_path
    out_dir = repo / "knowledge" / "candidates"
    candidate = {
        "card_title": "Corpus candidate",
        "knowledge_point": "A reusable corpus pattern",
        "source_report_ids": [123, 456],
        "worth_skill": True,
        "trigger_signals": ["signal"],
        "stop_conditions": ["stop"],
    }
    written = ingest_candidates(
        [candidate],
        out_dir=out_dir,
        register_lifecycle=True,
        repo_root=repo,
    )
    assert len(written) == 1
    lifecycle = out_dir / "lifecycle.jsonl"
    states, errors = candidates._state_map(lifecycle)
    assert not errors
    assert len(states) == 1
    state = next(iter(states.values()))
    assert state["sources"] == [
        {"type": "corpus-report", "report_id": "123"},
        {"type": "corpus-report", "report_id": "456"},
    ]


@pytest.mark.parametrize("source_ids", [[0], ["not-a-report"], [True], [123, 123]])
def test_distill_ingest_rejects_invalid_or_duplicate_corpus_ids(tmp_path, source_ids):
    out_dir = tmp_path / "knowledge" / "candidates"

    with pytest.raises(ValueError, match="source_report_ids"):
        ingest_candidates(
            [
                {
                    "card_title": "Invalid corpus source",
                    "knowledge_point": "Must not be staged",
                    "source_report_ids": source_ids,
                    "worth_skill": True,
                }
            ],
            out_dir=out_dir,
            register_lifecycle=True,
            repo_root=tmp_path,
        )

    assert not list(out_dir.glob("*.md"))
    assert not (out_dir / "lifecycle.jsonl").exists()


def test_candidate_source_audit_reuses_optional_case_resolver(tmp_path):
    repo = tmp_path
    out_dir = repo / "knowledge" / "candidates"
    ingest_candidates(
        [
            {
                "card_title": "Corpus candidate",
                "knowledge_point": "Resolver contract",
                "source_report_ids": [123, 456],
                "worth_skill": True,
                "trigger_signals": ["signal"],
                "stop_conditions": ["stop"],
            }
        ],
        out_dir=out_dir,
        register_lifecycle=True,
        repo_root=repo,
    )
    missing = candidates.audit_candidates(
        repo_root=repo,
        lifecycle_path=out_dir / "lifecycle.jsonl",
        source_mode="if-present",
    )
    assert missing["ok"] is True
    assert missing["skipped"]

    source = repo / "batch.jsonl"
    source.write_text(
        json.dumps(
            {
                "id": 123,
                "title": "fixture",
                "vulnerability_information": "steps",
                "weakness": "SSRF",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    corpus = repo / "distill" / "corpus"
    build_corpus([source], corpus_dir=corpus)

    resolved = candidates.audit_candidates(
        repo_root=repo,
        lifecycle_path=out_dir / "lifecycle.jsonl",
        source_mode="required",
        corpus_dir=corpus,
    )
    assert resolved["ok"] is False
    assert any("dangling corpus report 456" in error for error in resolved["errors"])


def test_candidate_audit_rejects_corpus_source_evidence_mismatch(tmp_path):
    repo = tmp_path
    out_dir = repo / "knowledge" / "candidates"
    ingest_candidates(
        [
            {
                "card_title": "Corpus candidate",
                "knowledge_point": "Resolver contract",
                "source_report_ids": [123],
                "worth_skill": True,
            }
        ],
        out_dir=out_dir,
        register_lifecycle=True,
        repo_root=repo,
    )
    lifecycle = out_dir / "lifecycle.jsonl"
    event = json.loads(lifecycle.read_text(encoding="utf-8"))
    event["evidence_refs"] = ["corpus-report:456"]
    lifecycle.write_text(json.dumps(event) + "\n", encoding="utf-8")

    result = candidates.audit_candidates(
        repo_root=repo,
        lifecycle_path=lifecycle,
        source_mode="off",
    )

    assert result["ok"] is False
    assert any("corpus sources/evidence_refs mismatch" in error for error in result["errors"])


def test_audit_rejects_orphan_candidate_file(tmp_path):
    repo = _repo_with_evidence(tmp_path)
    candidates_dir = repo / "knowledge" / "candidates"
    candidates_dir.mkdir(parents=True)
    (candidates_dir / "unregistered.md").write_text("# orphan\n", encoding="utf-8")

    result = candidates.audit_candidates(
        repo_root=repo,
        lifecycle_path=candidates_dir / "lifecycle.jsonl",
        strict=True,
    )

    assert result["ok"] is False
    assert any("orphan candidate file" in error for error in result["errors"])
