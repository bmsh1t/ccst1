"""distill_target: straight-line target-scoped knowledge distillation contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.distill_target import (
    TYPOLOGIES,
    build_prompt,
    commit_triple,
    _scrub_triple,
    _slugify,
    _validate_evidence_refs,
)


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


def _triple(ref: str, **overrides) -> dict:
    base = {
        "typology": "pattern",
        "pattern": "REST basket anonymous read",
        "trigger": "GET /rest/basket/<id> without auth returns other user data",
        "action": "three-way diff: anonymous / owner / peer id_swap",
        "evidence_refs": [ref],
    }
    base.update(overrides)
    return base


def test_prompt_pulls_ledger_and_emits_typology_question(tmp_path):
    _seed_target(tmp_path, "t.example")
    result = build_prompt(tmp_path, "t.example", "pattern")
    assert result["typology"] == "pattern"
    assert result["evidence_counts"]["ledger"] == 1
    assert "pattern" in result["question"]
    assert "/rest/basket/1" in result["question"]
    assert "evidence/t.example/probe/probe-1.json" in result["question"]


def test_prompt_rejects_unknown_typology(tmp_path):
    with pytest.raises(ValueError, match="unknown typology"):
        build_prompt(tmp_path, "t.example", "nope")


def test_commit_writes_draft_card_with_evidence_refs(tmp_path):
    _seed_target(tmp_path, "t.example")
    ref = "evidence/t.example/probe/probe-1.json"
    result = commit_triple(tmp_path, "t.example", json.dumps(_triple(ref)))
    assert result["status"] == "draft_written"
    card = Path(tmp_path, result["path"])
    text = card.read_text(encoding="utf-8")
    assert "maturity: draft" in text
    assert "type: technique-card" in text
    assert ref in text
    assert card.parent.name == "candidates"


def test_commit_scrubs_emails_and_tokens(tmp_path):
    scrubbed = _scrub_triple(
        _triple("x", pattern="contact admin@example.com with token ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
    )
    assert "admin@example.com" not in scrubbed["pattern"]
    assert "[email-redacted]" in scrubbed["pattern"]
    assert "[token-redacted]" in scrubbed["pattern"]


def test_commit_rejects_bare_ipv4_in_prose(tmp_path):
    _seed_target(tmp_path, "t.example")
    triple = _triple("evidence/t.example/probe/probe-1.json", pattern="server at 10.0.0.5 leaks data")
    with pytest.raises(ValueError, match="IPv4"):
        commit_triple(tmp_path, "t.example", json.dumps(triple))


def test_commit_rejects_credential_shaped_text(tmp_path):
    triple = _triple("x", action="send password: hunter2 to endpoint")
    with pytest.raises(ValueError, match="credential"):
        _scrub_triple(triple)


def test_commit_rejects_off_target_evidence_ref(tmp_path):
    _seed_target(tmp_path, "t.example")
    with pytest.raises(ValueError, match="not target-owned"):
        _validate_evidence_refs(tmp_path, "t.example", ["evidence/other.example/probe/x.json"])


def test_commit_rejects_missing_evidence_file(tmp_path):
    _seed_target(tmp_path, "t.example")
    with pytest.raises(ValueError, match="does not exist"):
        _validate_evidence_refs(tmp_path, "t.example", ["evidence/t.example/probe/missing.json"])


def test_commit_rejects_empty_evidence_refs(tmp_path):
    with pytest.raises(ValueError, match="at least one"):
        _validate_evidence_refs(tmp_path, "t.example", [])


def test_commit_requires_all_triple_fields(tmp_path):
    with pytest.raises(ValueError, match="'pattern' is required"):
        commit_triple(tmp_path, "t.example", json.dumps({"trigger": "t", "action": "a", "evidence_refs": []}))


def test_commit_slug_conflict_gets_serial_suffix(tmp_path):
    _seed_target(tmp_path, "t.example")
    ref = "evidence/t.example/probe/probe-1.json"
    first = commit_triple(tmp_path, "t.example", json.dumps(_triple(ref)))
    second = commit_triple(tmp_path, "t.example", json.dumps(_triple(ref)))
    assert first["path"] != second["path"]
    assert "-2" in second["path"]


def test_typologies_cover_vuln_memory_quartet():
    assert set(TYPOLOGIES) == {"pattern", "target-vuln", "failure", "bypass"}


def test_slugify_bounds_and_normalizes():
    assert _slugify("REST Basket 越权!! PATTERN") == "rest-basket-pattern"
    assert _slugify("") == "untitled"
    assert len(_slugify("a" * 200)) <= 48
