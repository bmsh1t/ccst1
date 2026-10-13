"""Synthetic, local-only recall generation and current-channel regression."""
from pathlib import Path

import pytest

from tools.experience_recall import query_recall, main
from tools.recall_index import build_text_index, index_status, prune_generations
from tools.target_store import TargetStore


def test_generation_current_stale_and_cli(tmp_path: Path, capsys):
    store = TargetStore(tmp_path, "recall.example")
    store.initialize()
    store.remember(command_id="handoff", kind="handoff", statement="Current handoff survives unrelated query",
                   conditions="test session", reopen_when="", next_intent="inspect current", evidence=[], actor="test")
    for i in range(3):
        store.remember(command_id=f"note-{i}", kind="note", statement=f"longtail matching {i}",
                       conditions="not valid for different actor", reopen_when="", next_intent="", evidence=[], actor="test")
    revision = store.binding()
    view = query_recall(tmp_path, target="recall.example", query="longtail", limit=1)
    assert view["current"]["memory"]["current_handoff"]["next_intent"] == "inspect current"
    assert view["health"]["semantic"]["status"] == "unavailable"
    assert not (tmp_path / "state/recall.example/recall-index").exists()
    first = build_text_index(tmp_path, "recall.example")
    status = index_status(tmp_path, "recall.example")
    assert status["partitions"]["target"]["health"]["status"] == "ready"
    assert status["health"]["status"] == "partial"
    assert query_recall(tmp_path, target="recall.example", query="longtail")["recalled"][0]["match"]["channel"] == "fts5-bm25"
    store.remember(command_id="later", kind="note", statement="longtail later", conditions="test session",
                   reopen_when="", next_intent="", evidence=[], actor="test")
    assert index_status(tmp_path, "recall.example")["partitions"]["target"]["health"]["status"] == "stale"
    with pytest.raises(ValueError, match="stale"):
        query_recall(tmp_path, target="recall.example", query="longtail", cursor=view["pagination"]["next_cursor"])
    build_text_index(tmp_path, "recall.example")
    assert prune_generations(tmp_path, "recall.example")["removed"] == [first["generation"]]
    assert main(["query", "--repo-root", str(tmp_path), "--target", "recall.example", "--limit", "1"]) == 0
    assert '"current"' in capsys.readouterr().out
    assert store.binding()["revision"] == revision["revision"] + 1


def test_source_admission_scope_complete_pages_and_missing_model(tmp_path, monkeypatch):
    import json
    from tools.recall_sources import acquire_snapshot
    from tools.recall_index import query_text
    from tools.recall_models import model_manifest, LocalModelError

    store = TargetStore(tmp_path, "recall.example")
    store.initialize()
    knowledge = tmp_path / "knowledge"
    (knowledge / "cards").mkdir(parents=True)
    (knowledge / "capabilities.yaml").write_text(
        "schema_version: 1\ncontracts: {}\ncapabilities:\n"
        "  - {id: draft, kind: card, file: knowledge/cards/draft.md}\n"
        "  - {id: tested, kind: card, file: knowledge/cards/tested.md}\n")
    (knowledge / "cards/draft.md").write_text("---\nmaturity: draft\n---\nnever reviewed\n")
    (knowledge / "cards/tested.md").write_text("---\nmaturity: tested\n---\nlongtail\n")
    snapshot = acquire_snapshot(tmp_path, "recall.example")
    assert all(doc["source_ref"] != "knowledge/cards/draft.md" for doc in snapshot["documents"])
    assert snapshot["current"]["scope"]["status"] == "ready"
    assert snapshot["health"]["knowledge"]["excluded"]
    snapshot["documents"] = [{"target": store.target, "source_ref": f"experience:{i}",
                               "source_hash": f"{i:064x}", "text": "longtail NOT permitted",
                               "conditions": "only same actor", "record": {}} for i in range(1007)]
    all_rows = query_text(tmp_path, "recall.example", snapshot, "NOT", limit=None)
    tail = query_text(tmp_path, "recall.example", snapshot, "NOT", offset=1000, limit=4)
    assert len(all_rows["items"]) == 1007
    assert tail["pagination"]["remaining"] == 3
    assert tail["items"] == all_rows["items"][1000:1004]
    foreign = {**snapshot, "documents": [{**snapshot["documents"][0], "target": "other.example"}]}
    with pytest.raises(ValueError, match="foreign"):
        query_text(tmp_path, "recall.example", foreign, "NOT")
    build_text_index(tmp_path, "recall.example", include_knowledge=False)
    pointer = tmp_path / "state/recall.example/recall-index/text/CURRENT"
    previous = pointer.read_bytes()
    manifest = build_text_index(tmp_path, "recall.example", encoder_path=tmp_path / "missing-model")
    assert manifest["partitions"]["target"]["manifest"] is None
    assert manifest["partitions"]["target"]["health"]["status"] == "unavailable"
    assert pointer.read_bytes() == previous
    snapshot = acquire_snapshot(tmp_path, "recall.example")
    missing = query_text(tmp_path, "recall.example", snapshot, "longtail", encoder_path=tmp_path / "missing-model")
    assert missing["health"]["semantic"]["status"] == "unavailable"
    assert not (tmp_path / "missing-model").exists()
    model = tmp_path / "model"
    model.mkdir()
    (model / "recall-model.json").write_text(json.dumps({"schema_version": 1, "role": "encoder",
        "version": "fixture", "sentence_transformers_version": "0", "dimension": 2,
        "max_seq_length": 128, "files": {"model.safetensors": "not-a-real-hash"}}))
    with pytest.raises(LocalModelError, match="files differ"):
        model_manifest(model, "encoder")


def test_shared_parse_reuse_keeps_review_admission_live(tmp_path, monkeypatch):
    import hashlib
    import tools.recall_sources as recall_sources

    store = TargetStore(tmp_path, "recall.example")
    store.initialize()
    knowledge = tmp_path / "knowledge"
    (knowledge / "cards").mkdir(parents=True)
    (knowledge / "capabilities.yaml").write_text(
        "schema_version: 1\ncontracts: {}\ncapabilities:\n"
        "  - id: reviewed\n    kind: card\n    file: knowledge/cards/reviewed.md\n"
        "    maturity: tested\n"
    )
    card = knowledge / "cards/reviewed.md"
    card.write_text("---\nid: reviewed\nmaturity: tested\n---\nshared parse body\n")
    calls = {"parse": 0, "review": 0, "relations": 0}
    parse = recall_sources.parse_knowledge_document
    relations = recall_sources.parse_method_relations

    def counted_parse(*args, **kwargs):
        calls["parse"] += 1
        return parse(*args, **kwargs)

    def live_review(_root, _entry, published, **_kwargs):
        calls["review"] += 1
        return {"status": "ready", "published_sha256": hashlib.sha256(published).hexdigest()}

    def counted_relations(*args, **kwargs):
        calls["relations"] += 1
        return relations(*args, **kwargs)

    monkeypatch.setattr(recall_sources, "parse_knowledge_document", counted_parse)
    monkeypatch.setattr(recall_sources, "read_published_review", live_review)
    monkeypatch.setattr(recall_sources, "parse_method_relations", counted_relations)

    first = build_text_index(tmp_path, "recall.example", shared=True, full_rebuild=True)
    after_first = dict(calls)
    second = build_text_index(tmp_path, "recall.example", shared=True)
    assert first["health"]["status"] == second["health"]["status"] == "ready"
    assert second["partitions"]["knowledge"]["update"]["reused_sources"] == 1
    assert calls["parse"] == after_first["parse"]
    assert calls["review"] > after_first["review"]
    assert calls["relations"] > after_first["relations"]

    card.write_text("---\nid: reviewed\nmaturity: tested\n---\nchanged body\n")
    changed = build_text_index(tmp_path, "recall.example", shared=True)
    assert changed["partitions"]["knowledge"]["update"]["updated_sources"] == 1
    assert changed["partitions"]["knowledge"]["update"]["reused_sources"] == 0
    assert calls["parse"] == after_first["parse"] + 1


def test_shared_partial_review_preserves_previous_generation(tmp_path, monkeypatch):
    import hashlib
    import tools.recall_sources as recall_sources

    store = TargetStore(tmp_path, "recall.example")
    store.initialize()
    knowledge = tmp_path / "knowledge"
    (knowledge / "cards").mkdir(parents=True)
    (knowledge / "capabilities.yaml").write_text(
        "schema_version: 1\ncontracts: {}\ncapabilities:\n"
        "  - id: reviewed\n    kind: card\n    file: knowledge/cards/reviewed.md\n"
        "    maturity: tested\n"
    )
    card = knowledge / "cards/reviewed.md"
    card.write_text("---\nid: reviewed\nmaturity: tested\n---\nshared parse body\n")

    def live_review(_root, _entry, published, **_kwargs):
        return {"status": "ready", "published_sha256": hashlib.sha256(published).hexdigest()}

    monkeypatch.setattr(recall_sources, "read_published_review", live_review)
    first = build_text_index(tmp_path, "recall.example", shared=True, full_rebuild=True)
    current = (tmp_path / ".cache/knowledge-recall/text/CURRENT").read_bytes()

    def withdrawn_review(_root, _entry, _published, **_kwargs):
        return {"status": "withdrawn", "reason": "fixture withdrawal"}

    monkeypatch.setattr(recall_sources, "read_published_review", withdrawn_review)
    second = build_text_index(tmp_path, "recall.example", shared=True)

    assert first["health"]["status"] == "ready"
    assert second["health"]["status"] != "ready"
    assert second["partitions"]["knowledge"]["manifest"] is None
    assert (tmp_path / ".cache/knowledge-recall/text/CURRENT").read_bytes() == current


def test_corrupt_shared_parse_dto_falls_back_to_reparse(tmp_path, monkeypatch):
    import hashlib
    import tools.recall_sources as recall_sources

    knowledge = tmp_path / "knowledge"
    (knowledge / "cards").mkdir(parents=True)
    (knowledge / "capabilities.yaml").write_text(
        "schema_version: 1\ncontracts: {}\ncapabilities:\n"
        "  - id: reviewed\n    kind: card\n    file: knowledge/cards/reviewed.md\n"
        "    maturity: tested\n"
    )
    (knowledge / "cards/reviewed.md").write_text(
        "---\nid: reviewed\nmaturity: tested\n---\ncanonical body\n"
    )
    monkeypatch.setattr(
        recall_sources,
        "read_published_review",
        lambda _root, _entry, published, **_kwargs: {
            "status": "ready",
            "published_sha256": hashlib.sha256(published).hexdigest(),
        },
    )
    calls = {"parse": 0}
    parse = recall_sources.parse_knowledge_document

    def counted_parse(*args, **kwargs):
        calls["parse"] += 1
        return parse(*args, **kwargs)

    monkeypatch.setattr(recall_sources, "parse_knowledge_document", counted_parse)
    _documents, _health, capture, first_stats = recall_sources.acquire_knowledge(
        tmp_path, return_parse_capture=True
    )
    assert first_stats["parsed_sources"] == 1
    assert calls["parse"] == 1

    corrupted = {**capture, "entries": {**capture["entries"]}}
    ref = "knowledge/cards/reviewed.md"
    corrupted["entries"][ref] = {**capture["entries"][ref], "body": "tampered body"}
    documents, _health, _capture, stats = recall_sources.acquire_knowledge(
        tmp_path, parsed_capture=corrupted, return_parse_capture=True
    )

    assert documents[0]["text"].endswith("canonical body\n")
    assert stats["parsed_sources"] == 1
    assert stats["reused_sources"] == 0
    assert calls["parse"] == 2


def test_float32_vector_rejects_malformed_provider_output():
    import math
    from tools.recall_models import LocalModelError, float32_vector

    assert float32_vector([1, 2], 2) == [1.0, 2.0]
    for values, dimension in (([1], 2), ([math.nan, 1], 2), (["1", 2], 2), (None, 2), ([0, 0], 2)):
        with pytest.raises(LocalModelError):
            float32_vector(values, dimension)


def test_provider_output_without_numpy_adapter_is_unavailable():
    from tools.recall_models import LocalModel, LocalModelError

    class BareModel:
        def encode(self, *_args, **_kwargs):
            return [[1.0, 0.0]]

        def predict(self, *_args, **_kwargs):
            return [0.5]

    model = object.__new__(LocalModel)
    model.model = BareModel()
    with pytest.raises(LocalModelError, match="local encoder failed"):
        model.encode(["fixture"])
    with pytest.raises(LocalModelError, match="local reranker failed"):
        model.score("query", ["fixture"])
