"""本地案例 corpus 的构建、完整性与按需查询行为测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import case_corpus
from case_corpus import (
    CaseCorpusError,
    build_corpus,
    corpus_status,
    from_card,
    get_case,
    main,
    search_cases,
)


def _report(report_id: int, *, weakness: str = "SSRF", title: str | None = None) -> dict:
    return {
        "id": report_id,
        "title": title or f"Report {report_id}",
        "vulnerability_information": f"完整复现步骤 {report_id}",
        "substate": "resolved",
        "weakness": {"name": weakness},
        "has_bounty?": True,
        "vote_count": report_id % 10,
        "reporter": {"username": "must-not-survive"},
        "team": {"handle": "must-not-survive"},
    }


def _write_jsonl(path: Path, rows: list[object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return path


def _write_card_repo(root: Path, refs: list[str]) -> None:
    registry = root / "knowledge" / "capabilities.yaml"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(
        """schema_version: 1
contracts: {}
capabilities:
  - id: demo-card
    kind: card
    file: knowledge/cards/demo-card.md
    layer: case-router
    load: on-demand
    purpose: case-lookup
    triggers: [demo]
""",
        encoding="utf-8",
    )
    source_refs = "\n".join(
        f"  - type: corpus-report\n    corpus: hackerone-disclosed-reports\n    id: \"{item}\""
        for item in refs
    )
    card = root / "knowledge" / "cards" / "demo-card.md"
    card.parent.mkdir(parents=True, exist_ok=True)
    card.write_text(
        f"""---
id: demo-card
source_refs:
{source_refs}
---
# Demo
""",
        encoding="utf-8",
    )


def test_missing_or_partial_corpus_is_non_blocking_unavailable(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"

    assert corpus_status(corpus_dir=corpus)["status"] == "unavailable"
    corpus.mkdir()
    (corpus / "reports.jsonl").write_text("", encoding="utf-8")
    result = corpus_status(corpus_dir=corpus)

    assert result["status"] == "unavailable"
    assert result["reason"] == "corpus-artifacts-missing"


def test_build_get_and_non_ascii_byte_offsets_round_trip(tmp_path: Path) -> None:
    source = _write_jsonl(
        tmp_path / "batch.jsonl",
        [
            _report(101, title="普通标题"),
            _report(102, weakness="Cross-Site Scripting", title="含中文的第二条案例"),
        ],
    )
    corpus = tmp_path / "corpus"

    built = build_corpus([source], corpus_dir=corpus)
    summary = get_case("102", corpus_dir=corpus)
    full = get_case(102, corpus_dir=corpus, full=True)

    assert built["records"] == 2
    assert corpus_status(corpus_dir=corpus)["status"] == "available"
    assert summary["status"] == "ok"
    assert summary["summary"]["title"] == "含中文的第二条案例"
    assert "vulnerability_information" not in summary["summary"]
    assert summary["payload"] is None
    assert full["payload"]["vulnerability_information"] == "完整复现步骤 102"
    assert set(full["payload"]) == {
        "id",
        "title",
        "vulnerability_information",
        "substate",
        "weakness",
        "has_bounty",
        "vote_count",
    }


def test_query_uses_fast_metadata_and_single_record_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_jsonl(tmp_path / "batch.jsonl", [_report(101), _report(102)])
    corpus = tmp_path / "corpus"
    build_corpus([source], corpus_dir=corpus)

    def reject_full_file_hash(_path: Path) -> str:
        raise AssertionError("ordinary query must not hash the complete corpus")

    monkeypatch.setattr(case_corpus, "_sha256_file", reject_full_file_hash)

    result = get_case("102", corpus_dir=corpus, full=True)

    assert result["status"] == "ok"
    assert result["payload"]["id"] == "102"


def test_duplicate_id_fails_before_replacing_previous_corpus(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    initial = _write_jsonl(tmp_path / "initial.jsonl", [_report(101)])
    build_corpus([initial], corpus_dir=corpus)
    duplicate = _write_jsonl(
        tmp_path / "duplicate.jsonl",
        [_report(201), _report(201, title="duplicate")],
    )

    with pytest.raises(CaseCorpusError, match="重复 report ID 201"):
        build_corpus([duplicate], corpus_dir=corpus)

    assert get_case("101", corpus_dir=corpus)["status"] == "ok"
    assert get_case("201", corpus_dir=corpus)["status"] == "not-found"


def test_malformed_input_does_not_publish_partial_corpus(tmp_path: Path) -> None:
    source = tmp_path / "bad.jsonl"
    source.write_text(json.dumps(_report(1)) + "\n{broken\n", encoding="utf-8")
    corpus = tmp_path / "corpus"

    with pytest.raises(CaseCorpusError, match="JSON 无效"):
        build_corpus([source], corpus_dir=corpus)

    assert corpus_status(corpus_dir=corpus)["status"] == "unavailable"


def test_stale_data_and_invalid_index_never_return_payload(tmp_path: Path) -> None:
    source = _write_jsonl(tmp_path / "batch.jsonl", [_report(101)])
    stale_corpus = tmp_path / "stale"
    build_corpus([source], corpus_dir=stale_corpus)
    with (stale_corpus / "reports.jsonl").open("ab") as handle:
        handle.write(b"{}\n")

    assert corpus_status(corpus_dir=stale_corpus)["status"] == "stale"
    assert get_case("101", corpus_dir=stale_corpus)["payload"] is None

    invalid_corpus = tmp_path / "invalid"
    build_corpus([source], corpus_dir=invalid_corpus)
    (invalid_corpus / "index.json").write_text("{broken", encoding="utf-8")
    invalid = corpus_status(corpus_dir=invalid_corpus)
    assert invalid["status"] == "invalid"
    assert get_case("101", corpus_dir=invalid_corpus)["status"] == "invalid"


def test_bad_offset_is_rejected_as_invalid(tmp_path: Path) -> None:
    source = _write_jsonl(tmp_path / "batch.jsonl", [_report(101)])
    corpus = tmp_path / "corpus"
    build_corpus([source], corpus_dir=corpus)
    index_path = corpus / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["by_id"]["101"]["offset"] = 10_000_000
    index_path.write_text(json.dumps(index), encoding="utf-8")

    result = corpus_status(corpus_dir=corpus)

    assert result["status"] == "invalid"
    assert "offset/length/sha256" in result["reason"]


def test_from_card_preserves_pointers_and_expands_at_most_one_case(tmp_path: Path) -> None:
    _write_card_repo(tmp_path, ["999", "102", "103"])
    source = _write_jsonl(tmp_path / "batch.jsonl", [_report(102), _report(103)])
    corpus = tmp_path / "corpus"
    build_corpus([source], corpus_dir=corpus)

    default = from_card("demo-card", repo_root=tmp_path, corpus_dir=corpus)
    full = from_card(
        "demo-card",
        repo_root=tmp_path,
        corpus_dir=corpus,
        report_id="103",
        full=True,
    )

    assert default["status"] == "ok"
    assert default["report_id"] == "102"
    assert default["dangling_refs"] == ["999"]
    assert default["payload"] is None
    assert default["pointers"] == ["999", "102", "103"]
    assert full["report_id"] == "103"
    assert full["payload"]["id"] == "103"
    assert from_card(
        "demo-card", repo_root=tmp_path, corpus_dir=corpus, full=True
    )["status"] == "invalid"


def test_from_card_missing_corpus_returns_structured_unavailable(tmp_path: Path) -> None:
    _write_card_repo(tmp_path, ["102"])

    result = from_card(
        "demo-card",
        repo_root=tmp_path,
        corpus_dir=tmp_path / "missing",
    )

    assert result["status"] == "unavailable"
    assert result["pointers"] == ["102"]
    assert result["summary"] is None
    assert result["payload"] is None


def test_unknown_card_or_report_is_structured_not_found(tmp_path: Path) -> None:
    _write_card_repo(tmp_path, ["102"])
    source = _write_jsonl(tmp_path / "batch.jsonl", [_report(102)])
    corpus = tmp_path / "corpus"
    build_corpus([source], corpus_dir=corpus)

    assert get_case("999", corpus_dir=corpus)["status"] == "not-found"
    assert from_card("missing", repo_root=tmp_path, corpus_dir=corpus)["status"] == "not-found"
    assert from_card(
        "demo-card", repo_root=tmp_path, corpus_dir=corpus, report_id="999"
    )["reason"] == "report-id-not-in-card-source-refs"


def test_search_is_casefolded_bounded_and_summary_only(tmp_path: Path) -> None:
    source = _write_jsonl(
        tmp_path / "batch.jsonl",
        [_report(3), _report(1), _report(2), _report(4, weakness="XSS")],
    )
    corpus = tmp_path / "corpus"
    build_corpus([source], corpus_dir=corpus)

    result = search_cases("ssrf", corpus_dir=corpus, limit=2)

    assert result["status"] == "ok"
    assert [item["id"] for item in result["results"]] == ["1", "2"]
    assert all("vulnerability_information" not in item for item in result["results"])


def test_cli_status_and_get_emit_stable_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = tmp_path / "repo"
    source = _write_jsonl(tmp_path / "batch.jsonl", [_report(101)])
    build_corpus([source], corpus_dir=repo / "distill" / "corpus")

    assert main(["--repo-root", str(repo), "status", "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["status"] == "available"
    assert main(["--repo-root", str(repo), "get", "101", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok"
    assert result["payload"] is None


def test_build_handles_ten_thousand_records_without_loading_bodies_for_query(tmp_path: Path) -> None:
    source = _write_jsonl(
        tmp_path / "batch-10k.jsonl",
        [_report(index, weakness="Fixture Class") for index in range(1, 10_001)],
    )
    corpus = tmp_path / "corpus"

    built = build_corpus([source], corpus_dir=corpus)
    selected = get_case("10000", corpus_dir=corpus, full=True)
    searched = search_cases("fixture class", corpus_dir=corpus, limit=20)

    assert built["records"] == 10_000
    assert selected["status"] == "ok"
    assert selected["payload"]["id"] == "10000"
    assert searched["count"] == 20
