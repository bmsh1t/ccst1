"""Tests for tools/context_pack.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import context_pack as context_pack_module
from autopilot_state import build_autopilot_state, load_closure_projection, stagnation_fingerprint
from context_pack import SKILL_CATALOG, SKILL_PATHS, build_context_pack, format_context_pack
from evidence_ledger import record_entry
from surface_projection import build_surface_input_manifest, write_surface_projection
from tools import knowledge_candidates as candidates
from tools.experience_schema import make_entry_id
from tools.target_paths import target_storage_key


def _seed_recon(repo_root: Path, target: str, urls: list[str]) -> None:
    recon_dir = repo_root / "recon" / target
    (recon_dir / "live").mkdir(parents=True)
    (recon_dir / "urls").mkdir(parents=True)
    (recon_dir / "js").mkdir(parents=True)
    (recon_dir / "browser").mkdir(parents=True)
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [FastAPI,React] [1000]\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "\n".join(urls) + "\n",
        encoding="utf-8",
    )
    (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
    (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")


def _seed_target_memory(repo_root: Path, target: str, payload: dict) -> None:
    goals_dir = repo_root / "memory" / "goals"
    target_dir = goals_dir / "targets"
    target_dir.mkdir(parents=True)
    (goals_dir / "active.json").write_text(
        json.dumps(
            {
                "target": target,
                "phase": "hunt",
                "active_goal": "Find high-value API authorization issues",
                "current_hypothesis": "org_id may be user-controlled",
            }
        ),
        encoding="utf-8",
    )
    merged = {"target": target}
    merged.update(payload)
    (target_dir / f"{target}.json").write_text(json.dumps(merged), encoding="utf-8")


def _seed_reviewed_candidate(
    repo_root: Path,
    *,
    source_target: str,
    title: str,
    summary: str,
    signals: list[str] | None,
) -> str:
    evidence_ref = f"memory/evidence/{target_storage_key(source_target)}/ledger.jsonl"
    evidence = repo_root / evidence_ref
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"result":"tested_clean"}\n', encoding="utf-8")
    entry_id = make_entry_id(
        target=source_target,
        field="useful_patterns",
        text=summary,
        evidence_refs=[evidence_ref],
    )
    target_path = (
        repo_root
        / "memory"
        / "goals"
        / "targets"
        / f"{target_storage_key(source_target)}.json"
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": source_target,
                "useful_patterns": [
                    {
                        "entry_id": entry_id,
                        "kind": "validation-technique",
                        "text": summary,
                        "evidence_refs": [evidence_ref],
                    }
                ],
                "dead_ends": [],
            }
        ),
        encoding="utf-8",
    )
    lifecycle = repo_root / "knowledge" / "candidates" / "lifecycle.jsonl"
    candidate_id, _ = candidates.stage_candidate(
        repo_root=repo_root,
        lifecycle_path=lifecycle,
        kind="validation-technique",
        title=title,
        summary=summary,
        source_pairs=[[source_target, entry_id]],
    )
    candidates._transition(
        candidate_id,
        action="reviewed",
        reviewer="human",
        reason="Reviewed for bounded cross-target recall.",
        recall_signals=signals,
        repo_root=repo_root,
        lifecycle_path=lifecycle,
    )
    return candidate_id


def _hint_paths(pack: dict) -> list[str]:
    return [item["path"] for item in pack.get("reference_hints", [])]


def test_bounded_context_readers_preserve_order_limits_and_error_handling(tmp_path):
    lines_path = tmp_path / "lines.txt"
    lines_path.write_bytes(b"\nalpha\nalpha\nbeta\n\xfftail\ngamma\n")
    jsonl_path = tmp_path / "items.jsonl"
    jsonl_path.write_text(
        '\n'.join(("not-json", '[1, 2]', '{"id": 1}', '{"id": 2}', '{"id": 3}')),
        encoding="utf-8",
    )

    assert context_pack_module._read_lines(lines_path, limit=3) == [
        "alpha",
        "beta",
        "\ufffdtail",
    ]
    assert context_pack_module._read_lines(lines_path, limit=0) == []
    assert context_pack_module._read_jsonl_objects(jsonl_path, limit=2) == [
        {"id": 1},
        {"id": 2},
    ]
    assert context_pack_module._read_jsonl_objects(jsonl_path, limit=0) == []


def test_context_pack_reuses_exact_surface_projection(tmp_path, monkeypatch):
    _seed_recon(
        tmp_path,
        "target.com",
        ["https://api.target.com/admin/orders?account_id=1"],
    )
    ranked = {
        "available": True,
        "target": "target.com",
        "p1": [
            {
                "url": "https://api.target.com/admin/orders?account_id=1",
                "score": 12,
                "reasons": ["projected candidate"],
                "suggested": "review authorization boundary",
            }
        ],
        "p2": [],
        "review_pool": [],
        "stats": {"total_candidates": 1, "p1": 1, "p2": 0, "review_pool": 0},
    }
    manifest = build_surface_input_manifest(tmp_path, "target.com")
    write_surface_projection(tmp_path, "target.com", ranked, manifest=manifest)

    def unexpected(*_args, **_kwargs):
        raise AssertionError("exact projection hit must not rebuild surface")

    monkeypatch.setattr(context_pack_module, "load_surface_context", unexpected)
    monkeypatch.setattr(context_pack_module, "rank_surface", unexpected)

    pack = build_context_pack(tmp_path, target="target.com", focus="api authorization")

    assert pack["source_summary"]["surface_available"] is True
    assert pack["source_summary"]["p1"] == 1
    assert any("admin/orders" in item for item in pack["evidence_anchors"])


def test_state_and_context_projection_are_semantically_repeatable(tmp_path):
    target = "target.com"
    memory_dir = tmp_path / "hunt-memory"
    first_state = build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))
    second_state = build_autopilot_state(str(tmp_path), target, memory_dir=str(memory_dir))
    first_pack = build_context_pack(
        tmp_path,
        target=target,
        memory_dir=str(memory_dir),
        surface_state=first_state["surface"],
    )
    second_pack = build_context_pack(
        tmp_path,
        target=target,
        memory_dir=str(memory_dir),
        surface_state=second_state["surface"],
    )
    first_closure_state = {
        **first_state,
        "next_action": "handoff",
        "json_inject": {"status": "partial", "input_fingerprint": "a" * 64, "request_count": 1},
    }
    second_closure_state = {
        **second_state,
        "next_action": "handoff",
        "json_inject": {"status": "partial", "input_fingerprint": "a" * 64, "request_count": 1},
    }
    first_closure = load_closure_projection(
        str(tmp_path), first_closure_state, max_lanes_reached=False
    )
    second_closure = load_closure_projection(
        str(tmp_path), second_closure_state, max_lanes_reached=False
    )

    assert {
        key: first_state[key]
        for key in ("next_action", "action_queue_next", "surface_projection", "sql_matrix")
    } == {
        key: second_state[key]
        for key in ("next_action", "action_queue_next", "surface_projection", "sql_matrix")
    }
    assert {
        key: first_pack[key]
        for key in (
            "selected_skill_id",
            "knowledge_cards",
            "deferred_knowledge_cards",
            "hypothesis_seeds",
            "source_summary",
        )
    } == {
        key: second_pack[key]
        for key in (
            "selected_skill_id",
            "knowledge_cards",
            "deferred_knowledge_cards",
            "hypothesis_seeds",
            "source_summary",
        )
    }
    assert {
        key: first_closure[key] for key in ("verdict", "reasons", "can_claim_exhausted")
    } == {
        key: second_closure[key] for key in ("verdict", "reasons", "can_claim_exhausted")
    }
    assert stagnation_fingerprint(first_closure_state, first_closure) == stagnation_fingerprint(
        second_closure_state, second_closure
    )


def test_context_pack_never_defaults_to_security_arsenal_skill():
    """Arsenal stays an on-demand reference layer, not a default selected Skill."""
    assert "security-arsenal" not in SKILL_PATHS
    assert all("skills/security-arsenal/SKILL.md" != path for path in SKILL_PATHS.values())


def test_skill_catalog_covers_repository_and_derives_primary_routes():
    repo = Path(__file__).resolve().parents[1]
    disk_skills = {
        path.parent.name for path in (repo / "skills").glob("*/SKILL.md")
    }

    assert set(SKILL_CATALOG) == disk_skills
    assert set(SKILL_PATHS) == {
        "bb-methodology",
        "bug-bounty",
        "credential-attack",
        "triage-validation",
        "web2-recon",
        "web2-vuln-classes",
    }


def test_explicit_primary_skill_names_precede_generic_validation_words(tmp_path):
    for skill_id in SKILL_PATHS:
        pack = build_context_pack(
            tmp_path,
            target="target.com",
            focus=f"{skill_id} candidate validation",
        )

        assert pack["selected_skill_id"] == skill_id
        assert pack["selected_skill"] == SKILL_PATHS[skill_id]
        assert pack["skill_route"]["required_dimensions"]


def test_api_idor_context_pack_selects_vuln_skill_and_cards(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/org/123/users?user_id=456",
    ])
    _seed_target_memory(tmp_path, "target.com", {
        "active_leads": [{"text": "/api/org/{id}/users may allow org swap"}],
    })

    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    output = format_context_pack(pack)

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["skill_route"]["skill_id"] == "web2-vuln-classes"
    assert "auth" in pack["skill_route"]["required_dimensions"]
    assert "knowledge/cards/api-idor.md" in pack["knowledge_cards"]
    assert "knowledge/cards/auth-access.md" in pack["knowledge_cards"]
    assert any("Surface review" in item for item in pack["evidence_anchors"])
    assert "AI override" in output


def test_context_pack_exposes_registry_metadata_for_selected_cards(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    caps = {item["file"]: item for item in pack["knowledge_card_capabilities"]}

    assert caps["knowledge/cards/api-idor.md"]["layer"] == "core"
    assert caps["knowledge/cards/api-idor.md"]["load"] == "signal-or-default"
    assert caps["knowledge/cards/api-idor.md"]["purpose"] == "validate"
    assert "Knowledge card capabilities:" in format_context_pack(pack)


def test_context_pack_exposes_bounded_historical_patterns_as_advisory(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="api-idor",
        surface_state={
            "available": True,
            "memory": {
                "pattern_suggestions": [
                    "target.com: current target replay [IDOR]",
                    "alpha.com: numeric ID swap [IDOR]",
                    "beta.com: sibling export replay [IDOR]",
                    "alpha.com: numeric ID swap [IDOR]",
                    "gamma.com: tenant header pivot [Authz]",
                    "delta.com: legacy API comparison [Authz]",
                ]
            },
        },
        coverage_state=([], {}),
    )

    assert pack["historical_patterns"] == [
        "numeric ID swap [IDOR]",
        "sibling export replay [IDOR]",
        "tenant header pivot [Authz]",
    ]
    assert pack["source_summary"]["historical_patterns"] == 3
    output = format_context_pack(pack)
    assert "Historical patterns (advisory; require current-target evidence):" in output
    historical_output = output.split("- Historical patterns", 1)[1].split("- Required checks", 1)[0]
    assert not any(domain in historical_output for domain in ("target.com", "alpha.com", "beta.com", "gamma.com", "delta.com"))


def test_context_pack_recalls_reviewed_candidate_from_english_focus(tmp_path):
    candidate_id = _seed_reviewed_candidate(
        tmp_path,
        source_target="source.example",
        title="Hidden binder from source.example",
        summary="Move a complete sibling parameter bundle before reducing fields.",
        signals=["hidden binder", "sibling parameter bundle"],
    )

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Review the hidden binder on an internal API",
    )
    output = format_context_pack(pack)

    assert pack["reviewed_candidate_hints"] == [
        {
            "candidate_id": candidate_id,
            "kind": "validation-technique",
            "title": "Hidden binder from [source-target]",
            "summary": "Move a complete sibling parameter bundle before reducing fields.",
            "advisory": "require current-target evidence",
        }
    ]
    assert pack["source_summary"]["reviewed_candidate_pool"] == 1
    assert pack["source_summary"]["reviewed_candidate_matches"] == 1
    assert pack["source_summary"]["reviewed_candidate_hints"] == 1
    assert "pool=1, matches=1, selected=1" in output
    assert "source.example" not in output


def test_context_pack_redacts_source_target_before_bounding_hint(tmp_path):
    _seed_reviewed_candidate(
        tmp_path,
        source_target="private-origin.example",
        title="x" * 155 + "private-origin.example",
        summary="Bound source-target removal before truncating display text.",
        signals=["hidden binder"],
    )

    pack = build_context_pack(
        tmp_path, target="target.com", focus="hidden binder"
    )

    assert "privat" not in pack["reviewed_candidate_hints"][0]["title"]


def test_context_pack_recalls_chinese_signal_from_target_evidence(tmp_path):
    _seed_target_memory(
        tmp_path,
        "target.com",
        {"active_leads": [{"text": "发现隐藏参数可能进入共享查询函数"}]},
    )
    candidate_id = _seed_reviewed_candidate(
        tmp_path,
        source_target="source.example",
        title="共享查询函数参数迁移",
        summary="先整束迁移，再缩减到实际生效字段。",
        signals=["隐藏参数", "共享查询函数"],
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert pack["reviewed_candidate_hints"][0]["candidate_id"] == candidate_id
    assert pack["source_summary"]["reviewed_candidate_matches"] == 1


def test_context_pack_candidate_nonmatches_are_visible_but_not_selected(tmp_path):
    _seed_reviewed_candidate(
        tmp_path,
        source_target="source.example",
        title="Header-only replay",
        summary="Use a narrow header replay when the proxy signal is present.",
        signals=["x-forwarded-for"],
    )

    pack = build_context_pack(tmp_path, target="target.com", focus="api authorization")
    output = format_context_pack(pack)

    assert pack["reviewed_candidate_hints"] == []
    assert pack["source_summary"]["reviewed_candidate_pool"] == 1
    assert pack["source_summary"]["reviewed_candidate_matches"] == 0
    assert "pool=1, matches=0, selected=0" in output


def test_context_pack_excludes_reviewed_candidate_without_recall_signals(tmp_path):
    _seed_reviewed_candidate(
        tmp_path,
        source_target="source.example",
        title="Legacy reviewed candidate",
        summary="A review without explicit signals remains manual-only.",
        signals=None,
    )

    pack = build_context_pack(
        tmp_path, target="target.com", focus="Legacy reviewed candidate"
    )

    assert pack["reviewed_candidate_hints"] == []
    assert pack["source_summary"]["reviewed_candidate_pool"] == 1
    assert pack["source_summary"]["reviewed_candidate_matches"] == 0


def test_context_pack_excludes_legacy_candidate_without_safe_projection(tmp_path):
    lifecycle = tmp_path / "knowledge" / "candidates" / "lifecycle.jsonl"
    staged = candidates._event(
        candidate_id="cand-legacy",
        action="staged",
        from_status=None,
        to_status="pending",
        candidate_path="knowledge/candidates/cand-legacy.md",
        sources=[
            {
                "type": "target-memory",
                "target": "source.example",
                "entry_id": "tm-legacy",
            }
        ],
        evidence_refs=["evidence/legacy.json"],
    )
    reviewed = candidates._event(
        candidate_id="cand-legacy",
        action="reviewed",
        from_status="pending",
        to_status="reviewed",
        candidate_path="knowledge/candidates/cand-legacy.md",
        reviewer="human",
        reason="Legacy review fixture.",
        recall_signals=["legacy binder"],
    )
    candidates._append_event(staged, path=lifecycle)
    candidates._append_event(reviewed, path=lifecycle)

    pack = build_context_pack(
        tmp_path, target="target.com", focus="legacy binder"
    )

    assert pack["reviewed_candidate_hints"] == []
    assert pack["source_summary"]["reviewed_candidate_pool"] == 0


def test_context_pack_excludes_pending_terminal_and_corpus_only_candidates(tmp_path):
    evidence = tmp_path / "memory" / "evidence" / "source" / "ledger.jsonl"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{}\n', encoding="utf-8")
    source_target = "source.example"
    summary = "Matching candidate fixture."
    entry_id = make_entry_id(
        target=source_target,
        field="useful_patterns",
        text=summary,
        evidence_refs=["memory/evidence/source/ledger.jsonl"],
    )
    _seed_target_memory(
        tmp_path,
        source_target,
        {
            "useful_patterns": [
                {
                    "entry_id": entry_id,
                    "kind": "validation-technique",
                    "text": summary,
                    "evidence_refs": ["memory/evidence/source/ledger.jsonl"],
                }
            ]
        },
    )
    lifecycle = tmp_path / "knowledge" / "candidates" / "lifecycle.jsonl"
    pending, _ = candidates.stage_candidate(
        repo_root=tmp_path,
        lifecycle_path=lifecycle,
        kind="validation-technique",
        title="Pending candidate",
        summary=summary,
        source_pairs=[[source_target, entry_id]],
    )
    terminal, _ = candidates.stage_candidate(
        repo_root=tmp_path,
        lifecycle_path=lifecycle,
        kind="dead-end",
        title="Terminal candidate",
        summary=summary,
        source_pairs=[[source_target, entry_id]],
    )
    candidates._transition(
        terminal,
        action="reviewed",
        reviewer="human",
        reason="Reviewed fixture.",
        recall_signals=["matching signal"],
        repo_root=tmp_path,
        lifecycle_path=lifecycle,
    )
    candidates._transition(
        terminal,
        action="rejected",
        reviewer="human",
        reason="Terminal fixture.",
        repo_root=tmp_path,
        lifecycle_path=lifecycle,
    )
    corpus_staged = candidates._event(
        candidate_id="cand-corpus",
        action="staged",
        from_status=None,
        to_status="pending",
        candidate_path="knowledge/candidates/cand-corpus.md",
        sources=[{"type": "corpus-report", "report_id": "1"}],
        evidence_refs=["corpus-report:1"],
        kind="validation-technique",
        title="Corpus candidate",
        summary=summary,
    )
    corpus_reviewed = candidates._event(
        candidate_id="cand-corpus",
        action="reviewed",
        from_status="pending",
        to_status="reviewed",
        candidate_path="knowledge/candidates/cand-corpus.md",
        reviewer="human",
        reason="Reviewed corpus fixture.",
        recall_signals=["matching signal"],
    )
    candidates._append_event(corpus_staged, path=lifecycle)
    candidates._append_event(corpus_reviewed, path=lifecycle)

    pack = build_context_pack(
        tmp_path, target="target.com", focus="matching signal"
    )

    assert pending != terminal
    assert pack["reviewed_candidate_hints"] == []
    assert pack["source_summary"]["reviewed_candidate_pool"] == 0


def test_context_pack_excludes_current_target_and_legacy_or_corrupt_candidates(tmp_path):
    _seed_reviewed_candidate(
        tmp_path,
        source_target="target.com",
        title="Current target only",
        summary="Current target experience must not validate itself.",
        signals=["authorization boundary"],
    )
    pack = build_context_pack(
        tmp_path, target="target.com", focus="authorization boundary"
    )
    assert pack["reviewed_candidate_hints"] == []
    assert pack["source_summary"]["reviewed_candidate_pool"] == 0

    lifecycle = tmp_path / "knowledge" / "candidates" / "lifecycle.jsonl"
    lifecycle.write_text("not-json\n", encoding="utf-8")
    corrupt = build_context_pack(
        tmp_path, target="target.com", focus="authorization boundary"
    )
    assert corrupt["reviewed_candidate_hints"] == []
    assert corrupt["source_summary"]["reviewed_candidate_pool"] == 0

    lifecycle.write_bytes(b"\xff\xfe\x00")
    invalid_encoding = build_context_pack(
        tmp_path, target="target.com", focus="authorization boundary"
    )
    assert invalid_encoding["reviewed_candidate_hints"] == []
    assert invalid_encoding["source_summary"]["reviewed_candidate_pool"] == 0


def test_context_pack_candidate_limit_does_not_change_card_budget(tmp_path):
    baseline = build_context_pack(
        tmp_path,
        target="target.com",
        focus="api hidden binder sibling parameter bundle",
    )
    first = _seed_reviewed_candidate(
        tmp_path,
        source_target="first.example",
        title="Binder candidate",
        summary="Short signal candidate.",
        signals=["hidden binder"],
    )
    second = _seed_reviewed_candidate(
        tmp_path,
        source_target="second.example",
        title="Parameter bundle candidate",
        summary="Longer signal candidate.",
        signals=["sibling parameter bundle"],
    )

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="api hidden binder sibling parameter bundle",
    )

    assert pack["source_summary"]["reviewed_candidate_pool"] == 2
    assert pack["source_summary"]["reviewed_candidate_matches"] == 2
    assert [item["candidate_id"] for item in pack["reviewed_candidate_hints"]] == [second]
    assert first != second
    assert pack["knowledge_cards"] == baseline["knowledge_cards"]
    assert pack["deferred_knowledge_cards"] == baseline["deferred_knowledge_cards"]


def test_context_pack_exposes_runner_candidates_without_marking_report_ready(tmp_path):
    validation_dir = tmp_path / "evidence" / "target.com" / "validation" / "idor-basket"
    validation_dir.mkdir(parents=True)
    (validation_dir / "summary.json").write_text(
        json.dumps(
            {
                "lane": "idor_actor_pair",
                "finding_id": "idor-basket",
                "url": "https://target.com/rest/basket/6",
                "method": "GET",
                "result": "tested_finding",
                "candidate_ready": True,
                "evidence_rubric": {
                    "status": "candidate-ready",
                    "ready": True,
                    "summary": "authz:candidate-ready",
                },
            }
        ),
        encoding="utf-8",
    )

    pack = build_context_pack(tmp_path, target="https://target.com/#/basket")
    output = format_context_pack(pack)

    assert pack["validation_runner_candidates"][0]["id"] == "idor-basket"
    assert any("Runner candidate evidence" in item for item in pack["evidence_anchors"])
    assert "Validation runner candidate evidence (advisory; not report-ready):" in output
    assert "requires /validate" in output


def test_context_pack_defers_extra_case_router_cards_instead_of_dropping(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="signature scope mismatch connection string jdbc driver option",
    )
    selected_layers = [item["layer"] for item in pack["knowledge_card_capabilities"]]
    deferred_layers = [item["layer"] for item in pack["deferred_knowledge_card_capabilities"]]

    assert selected_layers.count("case-router") == 1
    assert "case-router" in deferred_layers
    assert "knowledge/cards/signature-scope-mismatch.md" in (
        pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
    )
    assert "knowledge/cards/connection-string-injection.md" in (
        pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
    )


@pytest.mark.parametrize(
    "focus, expected_first",
    [
        (
            "SQLi request metadata hidden parameter",
            "knowledge/cards/sqli-hidden-surfaces.md",
        ),
        (
            "cloud metadata service SSRF internal",
            "knowledge/cards/cloud-control-plane-pivots.md",
        ),
        (
            "JWKS OIDC token verification",
            "knowledge/cards/auth-sso-token-edge-cases.md",
        ),
    ],
)
def test_collision_terms_keep_specific_recall_stable_and_explained(
    tmp_path,
    focus,
    expected_first,
):
    first = build_context_pack(tmp_path, target="target.com", focus=focus)
    second = build_context_pack(tmp_path, target="target.com", focus=focus)

    assert first["knowledge_cards"][0] == expected_first
    assert first["knowledge_cards"] == second["knowledge_cards"]
    assert first["deferred_knowledge_cards"] == second["deferred_knowledge_cards"]
    assert first["knowledge_card_recall"] == second["knowledge_card_recall"]
    assert len(first["knowledge_cards"]) <= 2
    all_cards = first["knowledge_cards"] + first["deferred_knowledge_cards"]
    assert len(all_cards) == len(set(all_cards))
    selected_recall = [
        item for item in first["knowledge_card_recall"] if item["status"] == "selected"
    ]
    assert [item["file"] for item in selected_recall] == first["knowledge_cards"]
    assert all("selected within card budget" in item["reason"] for item in selected_recall)


def test_generic_collision_word_does_not_take_a_core_card_slot(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="application metadata page documentation",
    )
    all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]

    assert pack["knowledge_cards"] == ["knowledge/cards/coverage-prompts.md"]
    assert not {
        "knowledge/cards/information-disclosure-source-config.md",
        "knowledge/cards/sqli-hidden-surfaces.md",
        "knowledge/cards/ssrf-internal-impact.md",
    }.intersection(all_cards)
    assert pack["knowledge_card_recall"] == [
        {
            "file": "knowledge/cards/coverage-prompts.md",
            "id": "coverage-prompts",
            "status": "selected",
            "rank": 1,
            "reason": "coverage or routing fallback; selected within card budget",
        }
    ]
    assert "Knowledge card recall:" in format_context_pack(pack)


def test_collision_recall_marks_budgeted_cards_as_deferred(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://target.com/"])
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="cloud metadata service SSRF internal",
    )
    recall_by_file = {item["file"]: item for item in pack["knowledge_card_recall"]}

    deferred = "knowledge/cards/ssrf-url-fetch.md"
    assert deferred in pack["deferred_knowledge_cards"]
    assert recall_by_file[deferred]["status"] == "deferred"
    assert "deferred by card budget" in recall_by_file[deferred]["reason"]


def test_reference_hints_are_added_only_for_evidence_specific_details(tmp_path):
    ssti_pack = build_context_pack(tmp_path, target="target.com", focus="ssti template injection")
    ssrf_pack = build_context_pack(tmp_path, target="target.com", focus="ssrf blacklist filter url parser bypass")
    dom_pack = build_context_pack(tmp_path, target="target.com", focus="dom xss source sink grep")
    recon_pack = build_context_pack(tmp_path, target="target.com", focus="recon ffuf semgrep endpoint discovery")

    assert "skills/security-arsenal/references/payload-families.md" in _hint_paths(ssti_pack)
    assert "skills/security-arsenal/references/bypass-patterns.md" in _hint_paths(ssrf_pack)
    assert "skills/security-arsenal/references/sink-and-grep-patterns.md" in _hint_paths(dom_pack)
    assert "skills/security-arsenal/references/recon-tool-usage.md" in _hint_paths(recon_pack)
    assert "Reference hints:" in format_context_pack(ssti_pack)


def test_reference_hints_do_not_add_noise_for_unrelated_focus(tmp_path):
    api_pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    validation_pack = build_context_pack(tmp_path, target="target.com", focus="candidate validation")

    assert api_pack["reference_hints"] == []
    assert validation_pack["reference_hints"] == []


def test_auth_hidden_focus_routes_to_hidden_switch_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://manage.target.com/api/login",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="auth-hidden login-bypass")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/auth-hidden-switches.md"
    assert "knowledge/cards/auth-access.md" in pack["knowledge_cards"]
    assert any("隐藏认证参数" in seed or "自有或测试账号" in seed for seed in pack["hypothesis_seeds"])


def test_auth_sso_focus_routes_to_token_edge_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://login.target.com/oauth/callback?code=abc&state=xyz",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="jwt oauth sso")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/auth-sso-token-edge-cases.md"
    assert "knowledge/cards/auth-access.md" in pack["knowledge_cards"]
    assert any("state/nonce/PKCE" in seed or "account-linking" in seed for seed in pack["hypothesis_seeds"])


def test_jwt_unverified_signature_focus_surfaces_claim_tamper_baseline(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="JWT authentication bypass unverified signature session token payload sub role admin",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/auth-sso-token-edge-cases.md"
    assert any("claim-only tamper" in seed and "无效签名" in seed for seed in pack["hypothesis_seeds"])
    assert any("key-source" in seed and "JWK/JKU/KID/alg confusion" in seed for seed in pack["hypothesis_seeds"])


def test_access_control_method_focus_routes_to_auth_access_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="method-based-access-control referer-based-access-control url-based-access-control",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/auth-access.md",
        "knowledge/cards/api-idor.md",
    ]
    assert any("GET vs POST" in seed or "X-Original-URL" in seed for seed in pack["hypothesis_seeds"])
    assert any("raw replay" in seed and "fetch" in seed for seed in pack["hypothesis_seeds"])
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_presigned_url_routes_to_existing_authz_cards_and_capability_gate(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="S3 presigned upload URL object tenant method expiry content-type",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/api-idor.md",
        "knowledge/cards/auth-access.md",
    ]
    assert any(
        "bearer capability" in seed
        and "owner/peer" in seed
        and "修改已签名 query" in seed
        for seed in pack["hypothesis_seeds"]
    )
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_observability_ids_route_to_idor_without_becoming_idor_evidence(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Jaeger OpenTelemetry trace ID exposes order object identifier",
    )
    all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert "knowledge/cards/api-idor.md" in all_cards
    assert "knowledge/cards/information-disclosure-source-config.md" in all_cards
    assert "knowledge/cards/path-pattern-management-exposure.md" in all_cards
    assert any(
        "只是 ID 来源" in seed and "owner/peer actor-object replay" in seed
        for seed in pack["hypothesis_seeds"]
    )
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_opa_cedar_routes_to_existing_authz_cards_and_pdp_pep_gate(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="OPA Cedar authorization policy decision enforcement PDP PEP tenant",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/auth-access.md",
        "knowledge/cards/api-idor.md",
    ]
    assert any(
        "PDP" in seed and "PEP" in seed and "具体未授权数据或状态影响" in seed
        for seed in pack["hypothesis_seeds"]
    )
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_broad_signed_trace_and_policy_words_do_not_trigger_api_authz_refinements(tmp_path):
    cases = (
        ("signed payload", ("knowledge/cards/api-idor.md", "knowledge/cards/auth-access.md")),
        ("trace", ("knowledge/cards/api-idor.md",)),
        ("policy decision", ("knowledge/cards/api-idor.md", "knowledge/cards/auth-access.md")),
        ("cedar tree", ("knowledge/cards/api-idor.md", "knowledge/cards/auth-access.md")),
    )
    for focus, forbidden_cards in cases:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]

        assert not any(card in all_cards for card in forbidden_cards), focus


def test_missing_parameter_focus_routes_to_discovery_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/search/records",
        "https://api.target.com/forms/query?filter=",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="missing-param parameter-null")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/missing-parameter-discovery.md"
    assert any(
        "parameter is null" in seed or "目标特定参数词表" in seed
        for seed in pack["hypothesis_seeds"]
    )
    assert any("批量枚举真实 PII" in seed for seed in pack["hypothesis_seeds"])


def test_path_pattern_focus_routes_to_management_exposure_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://www.target.com/app01/login.html",
        "https://www.target.com/app02/stats/records.json",
        "https://www.target.com/static/asset-manifest.json",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="path-pattern management-exposure")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/path-pattern-management-exposure.md"
    assert any("发现类 fuzz" in seed or "管理/监控/日志/统计/配置/记录" in seed for seed in pack["hypothesis_seeds"])
    assert any("不接管云资源" in seed for seed in pack["hypothesis_seeds"])


def test_observed_api_path_routes_to_bounded_ancestor_prefix_cards(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="observed API path https://target.com/prod-api/system/user/list",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert "knowledge/cards/api-testing-workflow.md" in pack["knowledge_cards"]
    assert "knowledge/cards/path-pattern-management-exposure.md" in pack["knowledge_cards"]
    assert any(
        "最多 3 个非根祖先前缀" in seed
        and "最多 12 个候选" in seed
        and "seed_refs" in seed
        for seed in pack["hypothesis_seeds"]
    )


def test_generic_path_does_not_route_to_ancestor_prefix_discovery(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="generic path https://target.com/about/company",
    )
    all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]

    assert "knowledge/cards/path-pattern-management-exposure.md" not in all_cards
    assert not any("最多 3 个非根祖先前缀" in seed for seed in pack["hypothesis_seeds"])


def test_context_pack_surfaces_actor_matrix_gaps(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/accounts/42/export?account_id=42",
    ])
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/api/accounts/42/export",
        vuln_class="IDOR",
        actor="owner",
        object_scope="own",
        variant="baseline",
        result="tested_clean",
    )

    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    output = format_context_pack(pack)

    assert pack["source_summary"]["evidence_ledger_entries"] == 1
    assert pack["source_summary"]["actor_matrix_gaps"] > 0
    assert "memory/evidence/target.com/ledger.jsonl" in pack["must_read"]
    assert any("Actor gap" in item and "peer" in item for item in pack["evidence_anchors"])
    assert any("tools/evidence_ledger.py" in item for item in pack["write_back"])
    assert "Actor matrix gaps:" in output


def test_graphql_focus_routes_to_graphql_card(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/graphql"])

    pack = build_context_pack(tmp_path, target="target.com", focus="graphql")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/graphql.md"


def test_graphql_node_global_id_does_not_route_to_node_runtime_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="GraphQL private posts node global ID introspection query fields",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/graphql.md"]


def test_sqli_focus_routes_to_hidden_surface_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/search?q=case",
        "https://api.target.com/api/internal/config",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="sqli hidden-param")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/sqli-hidden-surfaces.md"
    assert any("请求元数据" in seed or "二阶输入" in seed for seed in pack["hypothesis_seeds"])


def test_query_semantics_sqli_focus_keeps_visible_input_baseline(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SQL injection WHERE clause product category filter search sort pagination report export tenant scope hidden products",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/sqli-hidden-surfaces.md"
    assert any("显式查询语义输入" in seed and "分页" in seed and "租户" in seed for seed in pack["hypothesis_seeds"])


def test_api_price_mutation_focus_pairs_api_with_business_logic(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API testing unused endpoint product price PATCH method matrix buy checkout item",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/api-testing-workflow.md",
        "knowledge/cards/business-logic-state-machines.md",
    ]
    assert any("业务逻辑" in seed or "状态机" in seed for seed in pack["hypothesis_seeds"])


def test_api_parameter_pollution_focus_routes_to_api_workflow(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API server-side parameter pollution HPP duplicate query parameter backend request reset password field truncation",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/api-testing-workflow.md",
        "knowledge/cards/missing-parameter-discovery.md",
    ]
    assert "knowledge/cards/upload-parser.md" not in pack["knowledge_cards"]
    assert any("API 参数污染/HPP" in seed and "duplicate query/body" in seed for seed in pack["hypothesis_seeds"])


def test_api_mass_assignment_focus_pairs_api_and_business_logic(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API mass assignment over-posting PATCH user profile role isAdmin plan status verified approved",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/api-testing-workflow.md",
        "knowledge/cards/business-logic-state-machines.md",
    ]
    assert "knowledge/cards/upload-parser.md" not in pack["knowledge_cards"]
    assert any("mass assignment" in seed and "role/isAdmin/plan/status/verified/approved" in seed for seed in pack["hypothesis_seeds"])


def test_upload_import_focus_routes_to_upload_parser(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/import/preview",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="upload import")

    assert "knowledge/cards/upload-parser.md" in pack["knowledge_cards"]
    assert any("解析器" in seed for seed in pack["hypothesis_seeds"])


def test_svg_upload_xxe_focus_keeps_conversion_readback_evidence(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SVG image upload avatar XML parser XXE external entity server image conversion read-back",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/xxe-xml-parser.md",
        "knowledge/cards/upload-parser.md",
    ]
    assert any(
        "SVG/Office/XML" in seed and "转换/read-back" in seed and "上传请求" in seed
        for seed in pack["hypothesis_seeds"]
    )


def test_upload_execution_focus_routes_to_deep_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/upload/avatar",
    ])

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="file upload web shell avatar content-type bypass executable extension server path",
    )

    assert pack["knowledge_cards"][0] == "knowledge/cards/upload-to-execution.md"
    assert "knowledge/cards/upload-to-execution.md" in pack["knowledge_cards"]
    assert "knowledge/cards/controlled-rce-impact.md" in pack["knowledge_cards"]
    assert "knowledge/cards/upload-parser.md" not in pack["knowledge_cards"]
    assert any("存储路径 proof" in seed and "read-back proof" in seed for seed in pack["hypothesis_seeds"])
    assert any("原始 upload 请求" in seed and "read-back 请求" in seed for seed in pack["hypothesis_seeds"])
    assert any("候选形态" in seed and "不是固定字典" in seed for seed in pack["hypothesis_seeds"])
    assert any("multipart part Content-Type" in seed and "声明 MIME" in seed for seed in pack["hypothesis_seeds"])


def test_upload_execution_filename_path_traversal_keeps_storage_proof(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/my-account/avatar",
    ])

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="file upload web shell path traversal filename encoded parent segment avatar read-back executable",
    )

    assert pack["knowledge_cards"] == [
        "knowledge/cards/upload-to-execution.md",
        "knowledge/cards/controlled-rce-impact.md",
    ]
    assert any(
        "filename" in seed
        and "编码 parent segment" in seed
        and "原上传目录" in seed
        and "目标目录" in seed
        and "read-back" in seed
        for seed in pack["hypothesis_seeds"]
    )


def test_rce_focus_routes_to_controlled_impact_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/template/render",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="rce command-injection ssti")

    assert pack["knowledge_cards"][0] == "knowledge/cards/controlled-rce-impact.md"
    assert any("RCE/命令执行" in seed or "先证明 primitive" in seed for seed in pack["hypothesis_seeds"])


def test_os_command_injection_focus_surfaces_output_channel_baseline(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="OS command injection simple product stock checker raw output blind timing output redirection OAST",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/controlled-rce-impact.md"
    assert any(
        "baseline" in seed and "single separator" in seed and "visible output" in seed
        for seed in pack["hypothesis_seeds"]
    )
    assert any("候选形态" in seed and "不是固定字典" in seed for seed in pack["hypothesis_seeds"])
    assert any(
        "Blind" in seed
        and "timing" in seed
        and "output redirection" in seed
        and "read-back" in seed
        and "OAST" in seed
        for seed in pack["hypothesis_seeds"]
    )


def test_node_prototype_focus_routes_to_node_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/profile/preferences",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="node prototype-pollution")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/node-prototype-pollution.md"
    assert any("inert marker" in seed or "merge/path-set" in seed for seed in pack["hypothesis_seeds"])


def test_ranked_technology_stack_is_visible_without_bare_high_risk_routing(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        surface_state={
            "available": True,
            "review_pool": [{
                "url": "https://api.target.com/profile",
                "path": "/profile",
                "tech_stack": ["Java", "PHP", "Spring"],
                "reasons": [],
                "suggested": "review endpoint",
            }],
            "p1": [],
            "p2": [],
            "stats": {"p1": 0, "p2": 0, "review_pool": 1},
        },
    )

    all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
    assert pack["tech_stack"] == ["Java", "PHP", "Spring"]
    assert "Tech stack: Java, PHP, Spring" in format_context_pack(pack)
    assert "knowledge/cards/insecure-deserialization.md" not in all_cards
    assert "knowledge/cards/sqli-hidden-surfaces.md" not in all_cards


def test_node_stack_plus_json_shape_routes_to_node_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        surface_state={
            "available": True,
            "review_pool": [{
                "url": "https://api.target.com/api/preferences",
                "path": "/api/preferences",
                "tech_stack": ["Node.js", "Express"],
                "request_shapes": [{
                    "method": "POST",
                    "body": {"content_type_hint": "application/json"},
                }],
                "reasons": [],
                "suggested": "review JSON merge behavior",
            }],
            "p1": [],
            "p2": [],
            "stats": {"p1": 0, "p2": 0, "review_pool": 1},
        },
    )

    assert "knowledge/cards/node-prototype-pollution.md" in (
        pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
    )


def test_wordpress_stack_routes_to_existing_inventory_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        surface_state={
            "available": True,
            "review_pool": [{
                "url": "https://target.com/wp-json/",
                "path": "/wp-json/",
                "tech_stack": ["WordPress"],
                "reasons": [],
                "suggested": "review REST surface",
            }],
            "p1": [],
            "p2": [],
            "stats": {"p1": 0, "p2": 0, "review_pool": 1},
        },
    )

    assert "knowledge/cards/wordpress-surface-intelligence.md" in (
        pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
    )


def test_explicit_focus_wins_over_mixed_background_signals(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://login.target.com/oauth/callback?code=abc&state=xyz",
        "https://api.target.com/.well-known/jwks.json",
        "https://api.target.com/api/profile/preferences",
        "https://api.target.com/api/import?url=https://example.com/feed",
    ])
    goals_dir = tmp_path / "memory" / "goals"
    target_dir = goals_dir / "targets"
    target_dir.mkdir(parents=True)
    (goals_dir / "active.json").write_text(
        json.dumps(
            {
                "target": "target.com",
                "phase": "hunt",
                "active_goal": "Validate routing effects on safe synthetic target",
                "current_hypothesis": "OAuth account-linking and Node prototype pollution are both possible",
            }
        ),
        encoding="utf-8",
    )
    (target_dir / "target.com.json").write_text(
        json.dumps(
            {
                "target": "target.com",
                "active_leads": [
                    {"text": "OAuth account-linking lead"},
                    {"text": "Node Express lodash merge __proto__ lead"},
                ],
            }
        ),
        encoding="utf-8",
    )

    auth_pack = build_context_pack(tmp_path, target="target.com", focus="jwt oauth sso")
    node_pack = build_context_pack(tmp_path, target="target.com", focus="node prototype-pollution")

    assert auth_pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert auth_pack["knowledge_cards"][0] == "knowledge/cards/auth-sso-token-edge-cases.md"
    assert node_pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert node_pack["knowledge_cards"][0] == "knowledge/cards/node-prototype-pollution.md"


def test_ssrf_internal_focus_routes_to_internal_impact_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/import?url=https://example.com/feed",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="ssrf-internal metadata")

    assert pack["knowledge_cards"][0] == "knowledge/cards/ssrf-internal-impact.md"
    assert "knowledge/cards/ssrf-internal-impact.md" in pack["knowledge_cards"]
    assert any("SSRF 内部影响" in seed for seed in pack["hypothesis_seeds"])


def test_ssrf_localhost_admin_focus_routes_to_internal_impact(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SSRF stock check server-side fetch URL localhost admin internal system",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/ssrf-internal-impact.md"
    assert "knowledge/cards/ssrf-url-fetch.md" in pack["knowledge_cards"]
    assert any("SSRF 内部影响" in seed for seed in pack["hypothesis_seeds"])


def test_ssrf_blacklist_filter_focus_surfaces_parser_boundary_seed(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SSRF blacklist input filter stockApi localhost loopback path encoding double encoding admin status change",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/ssrf-internal-impact.md"
    assert "knowledge/cards/ssrf-url-fetch.md" in pack["knowledge_cards"]
    assert any("blocked baseline" in seed and "loopback/别名 host" in seed for seed in pack["hypothesis_seeds"])
    assert any("单/双编码 path" in seed and "原始请求/响应" in seed for seed in pack["hypothesis_seeds"])
    assert any("测试资源" in seed and "单目标最小证明" in seed for seed in pack["hypothesis_seeds"])


def test_internal_admin_without_fetch_context_does_not_load_ssrf_internal(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="internal admin panel access control management exposure",
    )

    assert "knowledge/cards/ssrf-internal-impact.md" not in pack["knowledge_cards"]
    assert pack["knowledge_cards"][0] == "knowledge/cards/auth-access.md"


def test_race_payment_focus_keeps_red_lines_loaded(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/checkout/payment",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="race payment otp")

    assert "knowledge/cards/race-conditions.md" in pack["knowledge_cards"]
    assert "rules/red-lines.md" in pack["required_checks"]
    assert any("高并发" in seed or "真实资金" in seed for seed in pack["hypothesis_seeds"])
    assert any(
        "合法单次 baseline" in seed
        and "协议能力探测" in seed
        and "最小同步触发" in seed
        for seed in pack["hypothesis_seeds"]
    )


def test_candidate_finding_routes_to_triage_validation(tmp_path):
    findings_dir = tmp_path / "findings" / "target.com"
    findings_dir.mkdir(parents=True)
    (findings_dir / "findings.json").write_text(
        json.dumps([
            {
                "id": "F-1",
                "endpoint": "/api/org/123/users",
                "vuln_class": "IDOR",
                "validation_status": "candidate",
            }
        ]),
        encoding="utf-8",
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert pack["selected_skill"] == "skills/triage-validation/SKILL.md"
    assert "rules/reporting.md" in pack["required_checks"]
    assert any("F-1" in item for item in pack["evidence_anchors"])


def test_explicit_focus_survives_when_recon_is_missing(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/api-idor.md",
        "knowledge/cards/auth-access.md",
    ]


def test_explicit_sqli_focus_without_recon_routes_to_vuln_skill(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="sqli hidden-param")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/sqli-hidden-surfaces.md"


def test_explicit_nosql_focus_without_recon_routes_to_nosql_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="nosql operator-injection")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/nosql-query-injection.md"]
    assert any("NoSQL" in seed or "operator" in seed for seed in pack["hypothesis_seeds"])


def test_nosql_expression_focus_does_not_match_express_node(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="NoSQL MongoDB category filter string expression syntax error boolean pair",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/nosql-query-injection.md"]


def test_explicit_xxe_focus_without_recon_routes_to_xml_parser_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="xxe xml-parser xinclude")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/xxe-xml-parser.md"]
    assert any("XML 解析面" in seed or "OAST callback" in seed for seed in pack["hypothesis_seeds"])


def test_xxe_error_reflection_focus_keeps_parser_evidence_gate(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XXE XML parser business field unexpected value reflected error external entity content-type application/xml",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/xxe-xml-parser.md"]
    assert any(
        "错误响应本身不是 XXE 证据" in seed
        and "反射无害 entity" in seed
        and "OAST" in seed
        for seed in pack["hypothesis_seeds"]
    )


def test_xxe_metadata_ssrf_focus_routes_to_parser_and_internal_impact(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XXE XML parser SSRF metadata IAM role credentials external entity reflected business field",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/xxe-xml-parser.md",
        "knowledge/cards/ssrf-internal-impact.md",
    ]
    assert any("错误响应本身不是 XXE 证据" in seed for seed in pack["hypothesis_seeds"])
    assert any("SSRF 内部影响" in seed and "不做内网扫描" in seed for seed in pack["hypothesis_seeds"])


def test_xinclude_form_parameter_focus_mentions_assembled_xml_path(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XInclude form parameter assembled into server-side XML productId stock checker namespace file read",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/xxe-xml-parser.md"]
    assert any("form/JSON" in seed and "组装进 XML" in seed and "XInclude" in seed for seed in pack["hypothesis_seeds"])


def test_explicit_path_traversal_focus_without_recon_routes_to_file_read_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="path-traversal lfi file-read")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/path-traversal-file-read.md"]
    assert any("文件选择器" in seed or "traversal 变体" in seed for seed in pack["hypothesis_seeds"])


def test_explicit_ssti_focus_without_recon_routes_to_template_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="ssti template-injection reflected message ERB code context sandbox user-supplied object",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/server-side-template-injection.md",
        "knowledge/cards/controlled-rce-impact.md",
    ]
    assert any("模板求值 primitive" in seed or "受控影响证明" in seed for seed in pack["hypothesis_seeds"])
    assert any("render/trigger" in seed and "输入步" in seed and "触发步" in seed for seed in pack["hypothesis_seeds"])
    assert any("候选形态" in seed and "不是固定字典" in seed and "fingerprint" in seed for seed in pack["hypothesis_seeds"])
    assert any("Code-context SSTI" in seed and "baseline -> 无害表达式 -> trigger render" in seed for seed in pack["hypothesis_seeds"])
    assert any("原始设置请求" in seed and "触发请求" in seed and "controlled-rce gate" in seed for seed in pack["hypothesis_seeds"])
    assert any("500/超时本身不是成功证据" in seed and "侧效应" in seed for seed in pack["hypothesis_seeds"])


def test_explicit_template_engine_focus_routes_to_ssti_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="erb ruby-template")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/server-side-template-injection.md"


def test_template_engine_context_focus_routes_to_ssti_not_node_runtime(tmp_path):
    focuses = [
        "Tornado template preferred name code context user supplied object documentation",
        "Mako template expression code context render trigger",
        "Handlebars template server side render helper sandbox",
    ]

    for focus in focuses:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)

        assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
        assert pack["knowledge_cards"][0] == "knowledge/cards/server-side-template-injection.md"
        assert "knowledge/cards/controlled-rce-impact.md" in pack["knowledge_cards"]
        assert "knowledge/cards/node-prototype-pollution.md" not in pack["knowledge_cards"]
        assert any("引擎名" in seed and "template/render/code-context" in seed for seed in pack["hypothesis_seeds"])


def test_explicit_deserialization_focus_without_recon_routes_to_deser_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="deserialization signed-object viewstate")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/insecure-deserialization.md",
        "knowledge/cards/controlled-rce-impact.md",
    ]
    assert any("Serialized session" in seed or "完整性 gate" in seed for seed in pack["hypothesis_seeds"])


def test_serialized_session_cookie_deserialization_prioritizes_integrity_and_state_tamper(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="insecure deserialization serialized session cookie base64 object admin role privilege escalation",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/insecure-deserialization.md"
    assert "Serialized session" in pack["hypothesis_seeds"][0]
    assert "完整性 gate" in pack["hypothesis_seeds"][0]
    assert any("role/admin/tenant/feature" in seed and "自有/测试账号" in seed for seed in pack["hypothesis_seeds"])
    assert any("可解码不等于漏洞" in seed and "gadget" in seed for seed in pack["hypothesis_seeds"])


def test_deserialization_type_and_application_gadget_focus_keeps_minimal_evidence_gate(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="deserialization serialized data types boolean string integer application functionality gadget delete file avatar object",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/insecure-deserialization.md"
    assert any("boolean/string/integer/null" in seed and "类型语义差异" in seed for seed in pack["hypothesis_seeds"])
    assert any("应用功能 gadget" in seed and "测试资源" in seed and "原始请求/响应证据" in seed for seed in pack["hypothesis_seeds"])


def test_explicit_browser_boundary_focus_without_recon_routes_to_client_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="cors csrf clickjacking dom-xss postmessage")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/browser-client-boundaries.md"]
    assert any("真实浏览器" in seed or "SameSite" in seed for seed in pack["hypothesis_seeds"])
    assert any("CSRF" in seed and "method swap" in seed and "duplicate-cookie" in seed for seed in pack["hypothesis_seeds"])
    assert any("SameSite" in seed and "sibling-domain" in seed and "cookie refresh" in seed for seed in pack["hypothesis_seeds"])
    assert any("Referer" in seed and "no-referrer" in seed and "弱字符串匹配" in seed for seed in pack["hypothesis_seeds"])
    assert any("trusted-origin" in seed and "执行 JS" in seed for seed in pack["hypothesis_seeds"])
    assert any("Clickjacking" in seed and "第三方 top origin" in seed for seed in pack["hypothesis_seeds"])
    assert any("预填" in seed and "提交值" in seed for seed in pack["hypothesis_seeds"])
    assert any("frame-buster" in seed and "sandbox" in seed for seed in pack["hypothesis_seeds"])
    assert any("iframe offset" in seed and "DOM XSS" in seed for seed in pack["hypothesis_seeds"])
    assert any("state transition" in seed and "每一步坐标" in seed for seed in pack["hypothesis_seeds"])


def test_cors_origin_credentials_focus_does_not_route_to_auth_access(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="CORS trusted origin null origin credentialed read Access-Control-Allow-Credentials",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/browser-client-boundaries.md"]
    assert "knowledge/cards/auth-access.md" not in pack["knowledge_cards"]
    assert "knowledge/cards/api-idor.md" not in pack["knowledge_cards"]


def test_explicit_dom_navigation_focus_routes_to_browser_boundary_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="open-redirect client-side-redirect cookie-manipulation dom-clobbering",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/browser-client-boundaries.md"]
    assert any("location.href" in seed or "navigation" in seed for seed in pack["hypothesis_seeds"])
    assert any("Cookie manipulation" in seed and "消费页" in seed for seed in pack["hypothesis_seeds"])
    assert any("DOM clobbering" in seed and "HTMLCollection" in seed for seed in pack["hypothesis_seeds"])
    assert any("sanitizer/filter" in seed and "属性清洗" in seed for seed in pack["hypothesis_seeds"])
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_explicit_proxy_cache_focus_without_recon_routes_to_proxy_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="host-header request-smuggling web-cache-poisoning cache-deception")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/proxy-cache-boundaries.md"]
    assert any("cache key" in seed or "smuggling" in seed for seed in pack["hypothesis_seeds"])
    assert any("victim request shape" in seed and "Vary/User-Agent/Accept" in seed for seed in pack["hypothesis_seeds"])
    assert any("unkeyed header resource import" in seed and "multiple-header redirect" in seed for seed in pack["hypothesis_seeds"])
    assert any("smuggling-to-cache poisoning" in seed and "body absorber" in seed and "miss -> 302 Location -> hit" in seed for seed in pack["hypothesis_seeds"])
    assert any("未被正常响应预热" in seed and "X-Cache: hit/Age" in seed for seed in pack["hypothesis_seeds"])
    assert any("H2.CL resource delivery" in seed and "victim JS import" in seed for seed in pack["hypothesis_seeds"])
    assert any("smuggling-to-WCD" in seed and "incomplete-header" in seed and "victim Cookie" in seed for seed in pack["hypothesis_seeds"])
    assert any("victim 是否已进入可投递节奏" in seed and "JS/CSS/image key" in seed and "未被正常响应预热" in seed for seed in pack["hypothesis_seeds"])
    assert any("response queue poisoning" in seed and "404 sentinel" in seed and "Set-Cookie" in seed for seed in pack["hypothesis_seeds"])
    assert any("capture-other-users" in seed and "URL 编码" in seed and "完整 Cookie line" in seed for seed in pack["hypothesis_seeds"])
    assert any("parameter cloaking" in seed and "fat GET" in seed and "URL normalization" in seed for seed in pack["hypothesis_seeds"])
    assert any("multi-entry poisoning" in seed and "cache key injection" in seed for seed in pack["hypothesis_seeds"])
    assert any("状态/语言/redirect" in seed and "victim navigation" in seed for seed in pack["hypothesis_seeds"])
    assert any("key oracle" in seed and "victim key collision" in seed for seed in pack["hypothesis_seeds"])
    assert any("internal fragment cache" in seed and "随机 query" in seed for seed in pack["hypothesis_seeds"])
    assert any("Web cache deception" in seed and "path mapping" in seed and "exact-match" in seed for seed in pack["hypothesis_seeds"])
    assert any("WCD" in seed and "CSRF token" in seed and "自动提交表单" in seed for seed in pack["hypothesis_seeds"])
    assert any("backend connection pool" in seed and "GGET" in seed and "GPOST" in seed for seed in pack["hypothesis_seeds"])
    assert any("H2.TE" in seed and "forbidden header" in seed and "静默过滤" in seed for seed in pack["hypothesis_seeds"])
    assert any("H2.CL" in seed and "content-length: 0" in seed and "DATA mismatch" in seed for seed in pack["hypothesis_seeds"])
    assert any("H2 CRLF header injection" in seed and "Transfer-Encoding: chunked" in seed and "真实 header" in seed for seed in pack["hypothesis_seeds"])
    assert any("request splitting" in seed and "GET /x HTTP/1.1" in seed and "404 sentinel" in seed for seed in pack["hypothesis_seeds"])
    assert any("differential 404" in seed and "队列污染" in seed for seed in pack["hypothesis_seeds"])
    assert any("front-end controls" in seed and "body absorber" in seed and "localhost" in seed for seed in pack["hypothesis_seeds"])
    assert any("smuggled reflected XSS" in seed and "victim-facing" in seed for seed in pack["hypothesis_seeds"])
    assert any("malformed method" in seed and "timing/desync/queue" in seed for seed in pack["hypothesis_seeds"])


def test_explicit_websocket_focus_without_recon_routes_to_realtime_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="websocket cswsh")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/websocket-realtime-api.md"]
    assert any("WebSocket" in seed or "Origin" in seed for seed in pack["hypothesis_seeds"])
    assert any("raw frame" in seed and "CSWSH exfil" in seed and "X-Forwarded-For" in seed for seed in pack["hypothesis_seeds"])


def test_websocket_cswsh_authz_origin_focus_does_not_route_to_idor(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="WebSockets cross-site websocket hijacking CSWSH origin message schema authz",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/websocket-realtime-api.md"]
    assert "knowledge/cards/auth-access.md" not in pack["knowledge_cards"]
    assert "knowledge/cards/api-idor.md" not in pack["knowledge_cards"]


def test_explicit_information_disclosure_focus_without_recon_routes_to_info_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="information-disclosure source-map debug")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/information-disclosure-source-config.md"]
    assert any("信息泄露" in seed or "source map" in seed for seed in pack["hypothesis_seeds"])


def test_information_disclosure_stack_trace_focus_does_not_route_to_race(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Information disclosure source map backup file debug stack trace config leak",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/information-disclosure-source-config.md"]
    assert "knowledge/cards/race-conditions.md" not in pack["knowledge_cards"]


def test_explicit_xss_focus_without_recon_routes_to_xss_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="xss reflected-xss stored-xss")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/xss-client-injection.md"]
    assert any("XSS" in seed or "真实浏览器执行证据" in seed for seed in pack["hypothesis_seeds"])
    assert "rules/playbook-router.md" not in pack["required_checks"]


def test_explicit_csp_focus_without_recon_routes_to_xss_and_browser_cards(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="csp content-security-policy sandbox-escape dangling-markup")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/xss-client-injection.md",
        "knowledge/cards/browser-client-boundaries.md",
    ]
    assert any("CSP" in seed and "script-src-elem" in seed for seed in pack["hypothesis_seeds"])
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_explicit_api_testing_focus_without_recon_routes_to_api_workflow(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="api testing rest-api openapi")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/api-testing-workflow.md",
        "knowledge/cards/api-idor.md",
    ]
    assert any("API testing" in seed or "endpoint+method+auth matrix" in seed for seed in pack["hypothesis_seeds"])
    assert "rules/playbook-router.md" not in pack["required_checks"]


def test_explicit_business_logic_focus_without_recon_routes_to_logic_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="business logic state-machine client-side-controls price-tamper",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/business-logic-state-machines.md"]
    assert any("业务逻辑" in seed or "状态机 baseline" in seed for seed in pack["hypothesis_seeds"])
    assert any("业务逻辑无结果" in angle for angle in pack["alternative_angles"])
    assert "rules/playbook-router.md" not in pack["required_checks"]


def test_explicit_password_reset_focus_without_recon_routes_to_auth_recovery_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="password reset broken-logic username-enumeration credential-attack mfa",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/auth-credential-recovery-flows.md",
        "knowledge/cards/auth-access.md",
    ]
    assert any("密码重置" in seed or "reset token" in seed for seed in pack["hypothesis_seeds"])
    assert any("认证恢复无结果" in angle for angle in pack["alternative_angles"])
    assert "rules/playbook-router.md" not in pack["required_checks"]


def test_explicit_web_llm_focus_without_recon_routes_to_llm_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="web-llm prompt-injection rag")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/web-llm-tool-chains.md"]
    assert any("Web LLM" in seed or "工具" in seed for seed in pack["hypothesis_seeds"])


def test_agent_lifecycle_signals_route_to_web_llm_card(tmp_path):
    signals = (
        "MCP tool description changed",
        "agent rug-pull observed",
        "shadow_tool conflict",
        "tool schema drift",
        "cross-session-memory propagation",
        "multi agent impersonation",
    )

    for signal in signals:
        pack = build_context_pack(tmp_path, target="target.com", focus=f"API testing {signal}")
        assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md", signal
        assert pack["knowledge_cards"][0] == "knowledge/cards/web-llm-tool-chains.md", signal
        assert "rules/playbook-router.md" in pack["required_checks"], signal
        assert any("基础设施" in seed and "影响" in seed for seed in pack["hypothesis_seeds"]), signal


def test_target_memory_agent_signal_routes_without_explicit_focus(tmp_path):
    _seed_target_memory(
        tmp_path,
        "target.com",
        {"active_leads": [{"text": "Observed cross-session memory propagation between agents"}]},
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert pack["knowledge_cards"][0] == "knowledge/cards/web-llm-tool-chains.md"


def test_broad_agent_signal_words_do_not_route_to_web_llm_card(tmp_path):
    for focus in (
        "OpenAPI schema drift",
        "database server schema drift",
        "crypto rug pull",
        "session memory cache",
        "shadow DOM component",
    ):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert "knowledge/cards/web-llm-tool-chains.md" not in pack["knowledge_cards"], focus


def test_unprotected_admin_access_control_prioritizes_auth_access(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Unprotected admin functionality unprotected admin panel delete user administrator-panel access control",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/auth-access.md"
    assert "knowledge/cards/path-pattern-management-exposure.md" in pack["knowledge_cards"]
    assert any("权限" in seed or "角色" in seed for seed in pack["hypothesis_seeds"])


def test_explicit_ssrf_internal_focus_without_recon_routes_to_vuln_skill(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="ssrf-internal metadata")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/ssrf-internal-impact.md"
    assert "knowledge/cards/ssrf-url-fetch.md" in pack["knowledge_cards"]


def test_explicit_oauth_focus_without_recon_routes_to_vuln_skill(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="oauth sso token-binding account-linking")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/auth-sso-token-edge-cases.md"
    assert "knowledge/cards/auth-access.md" in pack["knowledge_cards"]


def test_dead_end_new_surface_becomes_contradiction(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/graphql"])
    _seed_target_memory(tmp_path, "target.com", {
        "dead_ends": [{"text": "GraphQL introspection disabled; no operation names in JS"}],
    })

    pack = build_context_pack(tmp_path, target="target.com", focus="graphql")

    assert any(
        "Remembered dead end may have new evidence" in item
        for item in pack["contradictions"]
    )


def test_newer_ledger_closure_suppresses_stale_dead_end_contradiction(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/graphql"])
    _seed_target_memory(tmp_path, "target.com", {
        "dead_ends": [
            {
                "ts": "2026-01-01T00:00:00Z",
                "text": "GraphQL https://api.target.com/graphql introspection disabled; no operation names in JS",
            }
        ],
    })
    record_entry(
        tmp_path,
        target="target.com",
        endpoint="/graphql",
        vuln_class="GraphQL",
        result="dead_end",
        source="ai-review",
        workflow="pressure-test",
        notes="AI reviewed newer GraphQL evidence and closed the old dead-end contradiction.",
    )

    pack = build_context_pack(tmp_path, target="target.com", focus="graphql")

    assert all(
        "Remembered dead end may have new evidence" not in item
        for item in pack["contradictions"]
    )


def test_context_pack_ignores_unrelated_active_target_when_target_explicit(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/api/users?id=1"])
    goals_dir = tmp_path / "memory" / "goals"
    goals_dir.mkdir(parents=True)
    (goals_dir / "active.json").write_text(
        json.dumps({"target": "old-target.example", "active_goal": "stale"}),
        encoding="utf-8",
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert all("Active target memory points to" not in item for item in pack["contradictions"])
    assert pack["active_goal"] != "stale"
    assert not pack["active_goal"]


def test_context_pack_does_not_rewrite_surface_probe_log(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/search?q=%27%20or%20%271%27=%271",
        "https://api.target.com/api/org/123/users",
    ])
    probe_log = tmp_path / "recon" / "target.com" / "urls" / "_filtered_attack_probes.txt"
    probe_log.write_text("sentinel\n", encoding="utf-8")

    build_context_pack(tmp_path, target="target.com")

    assert probe_log.read_text(encoding="utf-8") == "sentinel\n"


def test_browser_observed_context_becomes_actionable_pack_evidence(tmp_path):
    _seed_recon(tmp_path, "target.com", [])
    browser_dir = tmp_path / "recon" / "target.com" / "browser"
    (browser_dir / "summary.json").write_text(
        json.dumps({"counts": {"xhr_endpoints": 1, "api_endpoints": 1}}),
        encoding="utf-8",
    )
    (browser_dir / "xhr_endpoints.txt").write_text(
        "https://app.target.com/api/admin/export?order_id=42\n",
        encoding="utf-8",
    )
    (browser_dir / "api_endpoints.txt").write_text(
        "https://app.target.com/api/admin/export?order_id=42\n",
        encoding="utf-8",
    )
    (browser_dir / "browser_params.txt").write_text(
        "https://app.target.com/api/admin/export?order_id=42 :: order_id\n",
        encoding="utf-8",
    )
    (browser_dir / "forms.json").write_text(
        json.dumps({"status": "extracted", "forms": [{"method": "POST", "action": "/settings/team"}]}),
        encoding="utf-8",
    )
    (browser_dir / "page_js_map.json").write_text(
        json.dumps(
            {
                "pages": {"https://app.target.com/admin": {"js_files": ["https://app.target.com/admin.js"]}},
                "js_index": {"https://app.target.com/admin.js": ["https://app.target.com/admin"]},
            }
        ),
        encoding="utf-8",
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert "recon/target.com/browser/xhr_endpoints.txt" in pack["must_read"]
    assert pack["source_summary"]["browser_xhr"] == 1
    assert pack["source_summary"]["browser_params"] == 1
    assert any("Browser XHR/API" in item and "order_id=42" in item for item in pack["evidence_anchors"])
    assert any("Browser param" in item and "order_id" in item for item in pack["evidence_anchors"])
    assert any("登录态" in item and "红线" in item for item in pack["hypothesis_seeds"])
    assert any("Playwright" in item for item in pack["alternative_angles"])
    assert "No browser-observed XHR/API context loaded." not in pack["unknowns"]


def test_browser_viewstate_form_routes_to_concrete_integrity_seed(tmp_path):
    _seed_recon(tmp_path, "target.com", [])
    browser_dir = tmp_path / "recon" / "target.com" / "browser"
    (browser_dir / "forms.json").write_text(
        json.dumps({
            "status": "extracted",
            "forms": [{
                "method": "POST",
                "action": "/account",
                "hidden_fields": ["__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"],
            }],
        }),
        encoding="utf-8",
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert pack["knowledge_cards"][0] == "knowledge/cards/insecure-deserialization.md"
    assert any("Browser form: POST /account hidden_fields=__VIEWSTATE" in item for item in pack["evidence_anchors"])
    seed = next(seed for seed in pack["hypothesis_seeds"] if "ViewState 表单先保存同页新鲜 GET 基线" in seed)
    assert "tools/aspnet_viewstate_knownkey.py" in seed
    assert "独立于 Telerik" in seed
    assert "不能把 ViewState/反序列化标为 N/A" in seed
    assert "tools/aspnet_viewstate_knownkey.py" in pack["must_read"]
    assert "tools/telerik_knownkey.py" not in pack["must_read"]
    assert pack["source_summary"]["viewstate_signal"] is True
    assert pack["source_summary"]["telerik_dialog_signal"] is False


def test_telerik_browser_signal_routes_to_offline_known_key_check_only(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://app.target.com/Telerik.Web.UI.WebResource.axd?type=rau"])

    pack = build_context_pack(tmp_path, target="target.com")

    assert pack["knowledge_cards"][0] == "knowledge/cards/insecure-deserialization.md"
    assert "tools/telerik_knownkey.py" in pack["must_read"]
    seed = next(seed for seed in pack["hypothesis_seeds"] if "telerik_knownkey.py" in seed)
    assert "项目内 Badsecrets ASP.NET/Telerik 密钥集" in seed
    assert "不能自动晋升 Candidate 或 Finding" in seed
    assert pack["source_summary"]["telerik_dialog_signal"] is True


def test_js_and_source_intel_are_loaded_as_context_pack_evidence(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://app.target.com/graphql"])
    js_intel_dir = tmp_path / "findings" / "target.com" / "js_intel"
    source_intel_dir = tmp_path / "findings" / "target.com" / "source_intel"
    js_intel_dir.mkdir(parents=True)
    source_intel_dir.mkdir(parents=True)
    (js_intel_dir / "hypotheses.json").write_text(
        json.dumps(
            {
                "endpoints": [
                    {
                        "method": "POST",
                        "path": "/api/accounts/42/export?account_id=42",
                        "source_file": "recon/target.com/js/admin.js",
                        "auth_required": "true",
                    }
                ],
                "attack_surface_leads": [
                    {
                        "title": "Admin export IDOR",
                        "category": "IDOR",
                        "next_action": "compare account_id across owned roles",
                    }
                ],
                "graphql_operations": [{"name": "ExportAccount", "type": "mutation"}],
            }
        ),
        encoding="utf-8",
    )
    (source_intel_dir / "routes.json").write_text(
        json.dumps(
            {
                "routes": [{"method": "GET", "route": "/api/accounts/:id/export"}],
                "graphql_operations": [{"operation": "mutation", "name": "ExportAccount"}],
            }
        ),
        encoding="utf-8",
    )
    (source_intel_dir / "hypotheses.jsonl").write_text(
        json.dumps(
            {
                "type": "idor",
                "candidate": "/api/accounts/:id/export",
                "reason": "route contains account object id",
                "source": "repo:admin.js",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert "findings/target.com/js_intel/hypotheses.json" in pack["must_read"]
    assert "findings/target.com/source_intel/hypotheses.jsonl" in pack["must_read"]
    assert pack["source_summary"]["js_intel_endpoints"] == 1
    assert pack["source_summary"]["source_intel_hypotheses"] == 1
    assert any("JS-reader endpoint" in item and "account_id" in item for item in pack["evidence_anchors"])
    assert any("Source-intel hypothesis [idor]" in item for item in pack["evidence_anchors"])
    assert any("JS-reader" in item and "交叉验证" in item for item in pack["hypothesis_seeds"])
    assert any("knowledge/cards/api-idor.md" == item for item in pack["knowledge_cards"])


def test_explicit_cache_focus_without_host_header_routes_to_proxy_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="web-cache-poisoning cache-deception")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/proxy-cache-boundaries.md"]
    assert any("cache key" in seed or "poisoning" in seed for seed in pack["hypothesis_seeds"])
    assert any("victim request shape" in seed and "Vary/User-Agent/Accept" in seed for seed in pack["hypothesis_seeds"])

def test_request_smuggling_capture_focus_ignores_csrf_cookie_evidence_noise(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="request smuggling capture other users requests CL.TE comment storage CSRF Cookie line Content-Length victim request",
    )

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/proxy-cache-boundaries.md"]
    assert "knowledge/cards/browser-client-boundaries.md" not in pack["knowledge_cards"]
    assert "knowledge/cards/web-llm-tool-chains.md" not in pack["knowledge_cards"]
    assert any(
        "capture-other-users" in seed
        and "会话/CSRF" in seed
        and "reset/重试" in seed
        and "完整 Cookie line" in seed
        for seed in pack["hypothesis_seeds"]
    )


def test_distilled_knowledge_cards_route_from_explicit_focus_without_recon(tmp_path):
    cases = [
        ("signature scope mismatch saml jwt jku kid duplicate assertion", "knowledge/cards/signature-scope-mismatch.md"),
        ("oauth sso trust email redirect_uri account takeover", "knowledge/cards/auth-sso-token-edge-cases.md"),
        ("view differential validation view consumption view canonicalization gap", "knowledge/cards/view-differential.md"),
        ("writable JSON role field is persisted then read by permission API and admin API", "knowledge/cards/view-differential.md"),
        ("validate-store superadmin unpaired surrogate JSON parser", "knowledge/cards/view-differential.md"),
        ("validate-proxy duplicate JSON key qty first key last key", "knowledge/cards/view-differential.md"),
        ("JSON parse serialize round-trip mismatch across services", "knowledge/cards/view-differential.md"),
        ("Validate-Store 未配对代理对导致角色规范化差异", "knowledge/cards/view-differential.md"),
        ("重复JSON键在校验视图和消费视图分别使用首键末键", "knowledge/cards/view-differential.md"),
        ("JSON解析后重新序列化结果不一致", "knowledge/cards/view-differential.md"),
        ("request smuggling h2 crlf te header injection response queue", "knowledge/cards/proxy-cache-boundaries.md"),
        ("path allowlist normalization weak string prefix bypass", "knowledge/cards/path-allowlist-normalization.md"),
        ("sanitizer parser xss dompurify mutation-xss second decode", "knowledge/cards/xss-client-injection.md"),
        ("csp bypass exfil script-src report-uri connect-src", "knowledge/cards/xss-client-injection.md"),
        ("connection string injection jdbc dsn driver option", "knowledge/cards/connection-string-injection.md"),
        ("runtime primitive override monkey patch same realm stringify", "knowledge/cards/node-prototype-pollution.md"),
        ("import migration trust restore backup import tenant import", "knowledge/cards/import-migration-trust.md"),
        ("stale derived authz revoked permission cache role cache", "knowledge/cards/stale-derived-authz.md"),
        ("connection reuse key backend connection pool tenant key", "knowledge/cards/connection-reuse-key.md"),
        ("redirect header leak authorization header cross-origin redirect", "knowledge/cards/redirect-header-leak.md"),
        ("xs-leak oracle timing image size resource timing", "knowledge/cards/xs-leak-oracle.md"),
        ("cli argument injection flag injection shell wrapper", "knowledge/cards/cli-argument-injection.md"),
        ("sqli non-parameterizable order by column name identifier", "knowledge/cards/sqli-hidden-surfaces.md"),
        ("type confusion controlflow string boolean array object", "knowledge/cards/type-confusion-controlflow.md"),
        ("llm invisible unicode tag prompt injection rag", "knowledge/cards/web-llm-tool-chains.md"),
        ("second-order sink delayed sink stored render", "knowledge/cards/second-order-sink.md"),
        ("payment logic rounding gateway recipient refund", "knowledge/cards/business-logic-state-machines.md"),
        ("postmessage trust message event origin targetOrigin", "knowledge/cards/browser-client-boundaries.md"),
        ("render pipeline ssrf pdf render screenshot service wkhtmltopdf", "knowledge/cards/render-pipeline-ssrf.md"),
    ]

    for focus, expected_card in cases:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert pack["knowledge_cards"][0] == expected_card


def test_json_view_differential_routing_is_precise_and_budgeted(tmp_path):
    collision = build_context_pack(
        tmp_path,
        target="target.com",
        focus="validate-proxy duplicate JSON key scalar array object first key last key",
    )
    assert collision["knowledge_cards"][0] == "knowledge/cards/view-differential.md"
    assert "knowledge/cards/type-confusion-controlflow.md" in collision["deferred_knowledge_cards"]
    assert "knowledge/cards/upload-parser.md" not in (
        collision["knowledge_cards"] + collision["deferred_knowledge_cards"]
    )
    assert sum(
        item["layer"] == "case-router"
        for item in collision["knowledge_card_capabilities"]
    ) == 1

    ordinary = build_context_pack(
        tmp_path,
        target="target.com",
        focus="ordinary JSON API response schema",
    )
    assert "knowledge/cards/view-differential.md" not in (
        ordinary["knowledge_cards"] + ordinary["deferred_knowledge_cards"]
    )

    ordinary_role = build_context_pack(
        tmp_path,
        target="target.com",
        focus="ordinary JSON API profile response includes a role field",
    )
    assert "knowledge/cards/view-differential.md" not in (
        ordinary_role["knowledge_cards"] + ordinary_role["deferred_knowledge_cards"]
    )

    pretest = build_context_pack(
        tmp_path,
        target="target.com",
        focus="可写 JSON 角色字段先存储，再由权限 API 和管理 API 读取",
    )
    assert pretest["knowledge_cards"][0] == "knowledge/cards/view-differential.md"

    stored = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Validate-Store superadmin unpaired surrogate JSON parser",
    )
    assert stored["knowledge_cards"][0] == "knowledge/cards/view-differential.md"
    assert "knowledge/cards/upload-parser.md" not in (
        stored["knowledge_cards"] + stored["deferred_knowledge_cards"]
    )

    raw_surrogate = build_context_pack(
        tmp_path,
        target="target.com",
        focus=r'匿名提交 {"role":"superadmin\ud888"} 后 Admin API 截断并授予权限',
    )
    assert raw_surrogate["knowledge_cards"][0] == "knowledge/cards/view-differential.md"

    valid_surrogate_pair = build_context_pack(
        tmp_path,
        target="target.com",
        focus=r'普通 JSON 昵称 {"name":"user\ud83d\ude00"}',
    )
    assert "knowledge/cards/view-differential.md" not in (
        valid_surrogate_pair["knowledge_cards"]
        + valid_surrogate_pair["deferred_knowledge_cards"]
    )


def test_public_package_history_routes_to_bounded_recon_intelligence(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="npm package history published artifact",
    )

    assert pack["selected_skill"] == "skills/web2-recon/SKILL.md"
    assert "knowledge/cards/public-package-artifact-intelligence.md" in pack["knowledge_cards"]
    assert any("digest/SHA-256" in seed and "不安装" in seed for seed in pack["hypothesis_seeds"])
    assert any("真实目标" in seed and "/intel" in seed for seed in pack["hypothesis_seeds"])


def test_container_image_history_routes_to_public_artifact_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="GHCR container image history and layer versions",
    )

    assert pack["selected_skill"] == "skills/web2-recon/SKILL.md"
    assert "knowledge/cards/public-package-artifact-intelligence.md" in pack["knowledge_cards"]


def test_dependency_confusion_keeps_ci_cd_and_artifact_cards(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="dependency confusion npm public registry package history",
    )

    all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
    assert "knowledge/cards/public-package-artifact-intelligence.md" in all_cards
    assert "knowledge/cards/cicd-trust-boundaries.md" in all_cards


def test_bare_package_build_and_image_do_not_route_to_public_artifact_card(tmp_path):
    for focus in ("package", "build", "image"):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]

        assert "knowledge/cards/public-package-artifact-intelligence.md" not in all_cards


def test_js_runtime_signature_signals_route_to_bounded_recon_branch(tmp_path):
    signals = (
        "js reverse request chain",
        "frontend signature reconstruction",
        "request initiator and local JS rebuild",
        "browser runtime hook for encrypted parameter",
        "first divergence in client request generation",
    )

    for focus in signals:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert pack["selected_skill"] == "skills/web2-recon/SKILL.md", focus
        assert pack["knowledge_cards"][0] == (
            "knowledge/cards/js-runtime-signature-reconstruction.md"
        ), focus
        assert any("first divergence" in seed for seed in pack["hypothesis_seeds"]), focus


def test_js_runtime_signature_broad_words_do_not_route_new_card(tmp_path):
    for focus in (
        "signature",
        "encryption",
        "hook",
        "browser " + ("x" * 121) + " runtime hook",
    ):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
        assert "knowledge/cards/js-runtime-signature-reconstruction.md" not in all_cards


def test_custom_protocol_signals_route_to_bounded_recon_branch(tmp_path):
    signals = (
        "custom binary protocol frame recovery",
        "protocol reverse and message dictionary",
        "PCAP framing with opcode and checksum",
        "MessagePack length prefix and state recovery",
        "private RPC TLV endian field",
    )

    for focus in signals:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert pack["selected_skill"] == "skills/web2-recon/SKILL.md", focus
        assert pack["knowledge_cards"][0] == (
            "knowledge/cards/custom-protocol-state-recovery.md"
        ), focus
        assert any("TCP segmentation" in seed for seed in pack["hypothesis_seeds"]), focus


def test_custom_protocol_broad_words_do_not_route_new_card(tmp_path):
    for focus in (
        "pcap",
        "protobuf",
        "state machine",
        "handshake",
        "pcap " + ("x" * 121) + " opcode",
    ):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
        assert "knowledge/cards/custom-protocol-state-recovery.md" not in all_cards


def test_custom_protocol_keeps_grpc_and_websocket_specialized_cards(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="custom binary protocol frame layout with gRPC protobuf and WebSocket",
    )

    all_cards = pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
    assert "knowledge/cards/custom-protocol-state-recovery.md" in all_cards
    assert "knowledge/cards/grpc-api-boundaries.md" in all_cards
    assert "knowledge/cards/websocket-realtime-api.md" in all_cards


def test_target_memory_runtime_signal_routes_without_explicit_focus(tmp_path):
    _seed_target_memory(
        tmp_path,
        "target.com",
        {"active_leads": [{"text": "request initiator captured; local JS rebuild pending"}]},
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert pack["selected_skill"] == "skills/web2-recon/SKILL.md"
    assert "knowledge/cards/js-runtime-signature-reconstruction.md" in pack["knowledge_cards"]
