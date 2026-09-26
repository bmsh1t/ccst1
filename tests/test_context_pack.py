"""Tests for tools/context_pack.py."""

from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml

import context_pack as context_pack_module
from autopilot_state import build_autopilot_state, load_closure_projection, stagnation_fingerprint
from checkpoint import build_checkpoint
from context_pack import build_context_pack, format_context_pack
from surface_projection import build_surface_input_manifest, write_surface_projection
from tools.target_store import TargetStore
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


@pytest.fixture
def pack_store(tmp_path):
    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    return store


def _remember_hypothesis(store, statement, command_id="hypothesis"):
    store.remember(
        command_id=command_id, kind="hypothesis", statement=statement,
        conditions="Observed fixture surface; not yet validated", reopen_when="New evidence",
        next_intent="Inspect the referenced surface", evidence=[], actor="operator",
    )


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


def test_context_pack_reuses_exact_surface_projection(tmp_path, monkeypatch, pack_store):
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

    monkeypatch.setattr(context_pack_module, "_load_surface_context", unexpected)
    monkeypatch.setattr(context_pack_module, "rank_surface", unexpected)

    pack = build_context_pack(tmp_path, target="target.com", focus="api authorization")

    assert pack["source_summary"]["surface_available"] is True
    assert pack["source_summary"]["p1"] == 1
    assert any("admin/orders" in item for item in pack["evidence_anchors"])


def test_primary_goal_memory_projection_uses_store_case_context(tmp_path):
    from tools.context_pack import _load_goal_memory
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    store.remember_hypothesis(
        command_id="hypothesis-1",
        hypothesis_id="H-1",
        vuln_class="authz",
        why_now="Peer and owner sessions are available",
        actor="operator",
    )

    projection = _load_goal_memory(tmp_path, "target.com")

    assert projection["source"]["kind"] == "store"
    assert projection["source"]["revision"] > 0
    assert projection["target"]["current_hypothesis"] == "Peer and owner sessions are available"
    assert projection["target_path"].endswith("state/target.com/metadata.sqlite3")


def test_primary_context_pack_exposes_one_store_revision_binding(tmp_path):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    pack = build_context_pack(tmp_path, target="target.com")

    binding = pack["source_summary"]
    assert binding["snapshot_status"] == "bound"
    assert binding["store_id"] == store.binding()["store_id"]
    assert binding["store_revision"] == store.binding()["revision"]


def test_primary_context_pack_reads_conditional_memory_without_sqlite_must_read(tmp_path):
    from tools.target_store import TargetStore

    target = "target.com"
    store = TargetStore(tmp_path, target)
    store.initialize()
    _record_primary_context_evidence(store, tmp_path, "negative")
    operation_id = store.page("operations")["items"][0]["id"]
    for index in range(7):
        store.remember(
            command_id=f"note-{index}", kind="negative" if index == 6 else "note",
            statement=f"Review condition {index}",
            conditions=f"tenant {index}", reopen_when=f"peer session {index}",
            next_intent=f"compare object {index}",
            evidence=[{"operation_id": operation_id, "step": 0}] if index == 6 else [],
            actor="operator",
        )

    revision = store.binding()["revision"]
    pack = build_context_pack(tmp_path, target=target)
    memory = pack["target_experiences"]
    output = format_context_pack(pack)

    assert memory["total"] == 7
    assert memory["remaining"] == 2
    assert len(memory["items"]) == 5
    assert memory["items"][0]["entry_id"] == "note-6"
    assert memory["items"][0]["kind"] == "negative"
    assert store.experience_page(limit=5, cursor=memory["next_cursor"])["items"][0]["id"] == "note-1"
    next_page = subprocess.run(
        [*shlex.split(memory["next_command"]), "--json"],
        capture_output=True, text=True, check=True,
    )
    assert "note-1" in next_page.stdout
    assert "metadata.sqlite3" not in " ".join(pack["must_read"])
    assert any("Store finding IDs" in item for item in pack["do_not_load"])
    assert all("findings.json" not in item for item in pack["do_not_load"])
    assert "conditions=\"tenant 6\"" in output
    assert "reopen_when=\"peer session 6\"" in output
    assert "next_intent=\"compare object 6\"" in output
    assert f"evidence={operation_id}:0" in output
    assert memory["next_command"] in output
    assert memory["expand_command"] in output
    assert "write the selected skill" not in pack["ai_override"]
    assert store.binding()["revision"] == revision


def _record_primary_context_evidence(store, repo_root, attempt_id, *, endpoint=None, family="Authz", actor="anonymous", object_scope="", variant=""):
    artifact = repo_root / "evidence" / target_storage_key(store.target) / f"{attempt_id}.txt"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("Recorded response", encoding="utf-8")
    store.start_attempt(
        attempt_id=attempt_id, source="native", started_at="2026-09-22T00:00:00Z", actor="operator",
    )
    store.record_execution(
        attempt_id=attempt_id, outcome="complete", actor="operator",
        observations=[{
            "endpoint": endpoint or f"https://{store.target}/{attempt_id}", "method": "GET", "family": family,
            "actor": actor, "object_scope": object_scope, "variant": variant,
            "observed_at": "2026-09-22T00:00:00Z", "description": "Recorded object response",
            "artifacts": {"response": artifact.relative_to(repo_root).as_posix()},
            "result": "tested_clean", "state_changing": False,
        }],
    )
    return artifact


@pytest.mark.parametrize("shortcut", ["foreign", "old_revision", "damaged_raw"])
def test_primary_context_pack_reloads_supplied_truth(tmp_path, shortcut):
    from tools.current_truth import current_cell_projection
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    source = store
    if shortcut == "foreign":
        source = TargetStore(tmp_path, "foreign.test")
        source.initialize()
    artifact = _record_primary_context_evidence(source, tmp_path, "first")
    truth = current_cell_projection(tmp_path, source.target)
    assert truth["source"]["status"] == "ready"
    before = store.binding()
    expected_entries = 1
    if shortcut == "foreign":
        expected_entries = 0
    elif shortcut == "old_revision":
        _record_primary_context_evidence(store, tmp_path, "second")
        expected_entries = 2
    else:
        artifact.write_text("Damaged response", encoding="utf-8")
        assert store.binding() == before

    pack = build_context_pack(tmp_path, target=store.target, ledger_truth=truth)

    summary = pack["source_summary"]
    assert summary["evidence_ledger_entries"] == expected_entries
    assert summary["evidence_source_status"] == ("partial" if shortcut == "damaged_raw" else "ready")
    assert summary["store_revision"] == store.binding()["revision"]
    assert "foreign.test" not in json.dumps(pack)


def test_primary_context_pack_does_not_adopt_supplied_projection_shortcuts(tmp_path):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    pack = build_context_pack(
        tmp_path, target=store.target,
        surface_state={"available": True, "target": "foreign.test", "stats": {"p1": 999}},
        coverage_state=([{"endpoint": "/foreign", "vuln_class": "Authz"}], {"endpoints": []}),
        validation_runner_candidates=[{"summary_path": "foreign.test/summary.json"}],
    )

    summary = pack["source_summary"]
    assert summary["surface_available"] is False
    assert summary["p1"] == summary["coverage_gaps"] == summary["validation_runner_candidates"] == 0
    assert pack["validation_runner_candidates"] == []
    assert "foreign.test" not in json.dumps(pack)


def test_primary_context_coverage_ignores_legacy_closure(tmp_path):
    from tools.coverage_matrix import _matrix_path, VULN_CLASSES
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    path = _matrix_path(tmp_path, store.target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"target": store.target, "endpoints": [{
        "endpoint": "/historical", "cells": {name: {"status": "tested_clean"} for name in VULN_CLASSES},
    }]}), encoding="utf-8")
    recon_urls = tmp_path / "recon" / store.target / "urls" / "all.txt"
    recon_urls.parent.mkdir(parents=True)
    recon_urls.write_text(f"https://{store.target}/current\n", encoding="utf-8")
    before = path.read_bytes(), path.stat().st_mtime_ns, store.binding()
    pack = build_context_pack(tmp_path, target=store.target)
    assert pack["source_summary"]["coverage_gaps"] == len(VULN_CLASSES)
    assert "/historical" not in json.dumps(pack)
    assert (path.read_bytes(), path.stat().st_mtime_ns, store.binding()) == before


def test_primary_context_pack_rejects_revision_change_during_assembly(tmp_path, monkeypatch):
    from tools.target_store import TargetStore

    store = TargetStore(tmp_path, "target.com")
    store.initialize()
    original = TargetStore.binding
    first = original(store)
    changed = {**first, "revision": first["revision"] + 1}
    bindings = iter((first,))
    monkeypatch.setattr(TargetStore, "binding", lambda self: next(bindings, changed))

    with pytest.raises(ValueError, match="changed during assembly"):
        build_context_pack(tmp_path, target="target.com")


def test_state_and_context_projection_are_semantically_repeatable(tmp_path, pack_store):
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
            "knowledge_cards",
            "deferred_knowledge_cards",
            "hypothesis_seeds",
            "source_summary",
        )
    } == {
        key: second_pack[key]
        for key in (
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


def test_context_pack_leaves_skill_discovery_to_native_platform(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com")
    assert "skill_catalog" not in pack
    assert "selected_skill" not in pack
    assert "skill_route" not in pack


def test_must_read_omits_absent_target_state_paths(tmp_path, pack_store):
    """K-1: after a reset/fresh start, goal-memory files legitimately do not
    exist. must_read must not point at them — a contract listing missing
    files gives the reader no way to tell a defect from a fresh start. Repo
    contract documents stay unconditional."""
    pack = build_context_pack(tmp_path, target="target.com")

    assert "memory/goals/active.json" not in pack["must_read"]
    assert "memory/goals/targets/target.com.json" not in pack["must_read"]
    assert "skills/runtime-protocol.md" in pack["must_read"]
    assert "Showing 0 of 0; 0 more." in format_context_pack(pack)


def test_skills_and_cards_stay_outside_must_read(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    repo = Path(__file__).resolve().parents[1]
    skill_paths = {str(path.relative_to(repo)) for path in (repo / "skills").glob("*/SKILL.md")}

    assert "CLAUDE.md" not in pack["must_read"]
    assert "SKILL.md" not in pack["must_read"]
    assert "skills/runtime-protocol.md" in pack["must_read"]
    # S1 native loading: no recommendation and no duplicated catalog — the
    # platform's native skill listing is the routing surface.
    assert "selected_skill" not in pack
    assert "skill_route" not in pack
    assert "skill_catalog" not in pack
    assert set(pack["must_read"]).isdisjoint(skill_paths)
    assert len(pack["knowledge_cards"]) <= 2
    assert set(pack["knowledge_cards"]).isdisjoint(pack["must_read"])


@pytest.mark.parametrize(
    ("focus", "expected_card"),
    [
        ("sqli", "sqli-hidden-surfaces"),
        ("auth-hidden", "auth-hidden-switches"),
        ("missing-param", "missing-parameter-discovery"),
        ("path-pattern", "path-pattern-management-exposure"),
        ("api-idor", "api-idor"),
        ("ssrf", "ssrf-url-fetch"),
    ],
)
def test_command_and_autopilot_state_recall_share_candidates(tmp_path, capsys, focus, expected_card, pack_store):
    """Check deterministic entry parity, not live model discovery or file reads."""
    _seed_recon(tmp_path, "target.com", ["https://target.com/"])
    memory_dir = str(tmp_path / "hunt-memory")
    state = build_autopilot_state(str(tmp_path), "target.com", memory_dir=memory_dir)
    state_pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus=focus,
        memory_dir=memory_dir,
        surface_state=state["surface"],
    )
    assert context_pack_module.main([
        "target.com", focus, "--repo-root", str(tmp_path),
        "--memory-dir", memory_dir, "--json",
    ]) == 0
    command_pack = json.loads(capsys.readouterr().out)

    for key in (
        "target", "focus", "knowledge_cards",
        "deferred_knowledge_cards", "knowledge_card_recall",
    ):
        assert command_pack[key] == state_pack[key], key
    # 语义选卡退役（2026-09-13）：两条入口的 parity 仍在；卡片不再由 focus
    # 关键词预选，目录是发现面。
    assert command_pack["knowledge_cards"] == []
    assert expected_card in {
        item.get("id") for item in command_pack.get("card_catalog", [])
    }


def test_every_disk_skill_is_published_with_description_for_native_selection(tmp_path):
    """S1 native loading (batch 3): every skill on disk carries its frontmatter
    description (the native routing surface) — including direct-only /
    reference-only / report-only modes. The pack no longer ranks or lists them;
    verify the routing surface is the SKILL.md frontmatter itself."""
    repo = Path(__file__).resolve().parents[1]
    for skill_file in sorted((repo / "skills").glob("*/SKILL.md")):
        skill_id = skill_file.parent.name
        assert skill_file.is_file(), skill_id
        text = skill_file.read_text(encoding="utf-8", errors="replace").splitlines()
        assert text and text[0].strip() == "---", skill_id
        frontmatter = []
        for line in text[1:]:
            if line.strip() == "---":
                break
            frontmatter.append(line)
        assert any(l.startswith("name:") and l.split(":", 1)[1].strip() == skill_id for l in frontmatter), skill_id
        assert any(l.startswith("description:") and l.split(":", 1)[1].strip() for l in frontmatter), skill_id


def test_native_pilot_recommendation_surface_fully_retired(tmp_path, pack_store):
    """S1 batch 3 superseded the bb-methodology pilot: the pack recommends no
    skill at all (empty compatibility shells) and does not duplicate the
    platform's skill listing. The pilot-era `native_skills` field is gone."""
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/"])

    pack = build_context_pack(tmp_path, target="target.com", focus="api idor")
    output = format_context_pack(pack)

    for key in ("selected_skill", "selected_skill_id", "why_this_skill", "skill_route"):
        assert key not in pack
    assert "native_skills" not in pack
    assert "skill_catalog" not in pack
    assert "Skill recommendation retired (S1 native loading)" in output


def test_retired_context_sections_are_json_only(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com")
    pack["facts"] = [{"key": "confirmed", "text": "Keep this confirmed fact"}]
    before = json.dumps(pack, sort_keys=True)

    for key in (
        "knowledge_cards", "deferred_knowledge_cards", "knowledge_card_recall",
        "reference_hints", "hypothesis_seeds", "alternative_angles",
    ):
        assert pack[key] == []

    output = format_context_pack(pack)

    for heading in (
        "- Retired card projections", "- Reference hints",
        "- Hypothesis seeds:", "- Alternative angles:",
    ):
        assert heading not in output
    for heading in (
        "- Knowledge card catalog:", "- Required checks:",
        "- Evidence anchors:", "- Unknowns:", "- Write-back:",
    ):
        assert heading in output
    assert "Keep this confirmed fact" in output
    assert json.dumps(pack, sort_keys=True) == before


def test_memory_continuity_no_longer_drives_recommendation(tmp_path, pack_store):
    """Target-memory `selected_skills` is historical continuity data; with the
    recommendation layer retired it can no longer put a skill into the pack's
    recommendation slot. The AI reads it from memory and loads skills itself."""
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/"])
    historical = tmp_path / "memory/goals/targets/target.com.json"
    historical.parent.mkdir(parents=True)
    historical.write_text(json.dumps({"target": "target.com", "selected_skills": ["web2-vuln-classes"]}))

    pack = build_context_pack(tmp_path, target="target.com")

    assert "selected_skill_id" not in pack
    assert "skill_route" not in pack


def test_api_idor_context_pack_selects_vuln_skill_and_cards(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/org/123/users?user_id=456",
    ])
    _remember_hypothesis(pack_store, "/api/org/{id}/users may allow org swap")

    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    output = format_context_pack(pack)

    # Word-list skill routing is retired: the suggestion comes from owner
    # facts only, so a category-naming focus no longer forces the vuln skill.
    # What must hold: the pack publishes the full card catalog and the
    # focus-named card, and the override contract stays visible.
    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}
    catalog_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "api-idor" in catalog_ids
    assert "auth-sso-token-edge-cases" in catalog_ids, "full catalog published, not a filtered subset"
    assert any("Surface review" in item for item in pack["evidence_anchors"])
    assert "AI override" in output


def test_context_pack_exposes_registry_metadata_for_selected_cards(tmp_path, pack_store):
    # 语义选卡退役：registry metadata（layer/load/purpose）的发现面是
    # card_catalog —— 每张登记卡都带完整 capability 行，选择权在 AI。
    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    caps = {item["file"]: item for item in pack.get("card_catalog", [])}

    assert caps["knowledge/cards/api-idor.md"]["layer"] == "core"
    assert caps["knowledge/cards/api-idor.md"]["load"] == "signal-or-default"
    assert caps["knowledge/cards/api-idor.md"]["purpose"] == "validate"
    assert "Knowledge card catalog:" in format_context_pack(pack)


def test_target_registry_remap_reaches_context_pack_checkpoint_and_witness(tmp_path, pack_store):
    registry_source = Path(__file__).resolve().parents[1] / "knowledge" / "capabilities.yaml"
    registry = yaml.safe_load(registry_source.read_text(encoding="utf-8"))
    custom_card = "knowledge/cards/target-ssti.md"
    original_card = "knowledge/cards/server-side-template-injection.md"
    capability = next(
        item
        for item in registry["capabilities"]
        if item.get("id") == "server-side-template-injection"
    )
    capability["file"] = custom_card
    registry_path = tmp_path / "knowledge" / "capabilities.yaml"
    registry_path.parent.mkdir(parents=True)
    registry_path.write_text(
        yaml.safe_dump(registry, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    card_path = tmp_path / custom_card
    card_path.parent.mkdir(parents=True, exist_ok=True)
    card_path.write_text("# Target SSTI card\n", encoding="utf-8")
    pack_store.set_active_goal(command_id="goal", goal="Validate one template rendering boundary", actor="operator")
    _remember_hypothesis(pack_store, "SSTI template injection render payload family")

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="ssti template injection render payload family",
    )

    # After retiring word-list auto-selection, a remapped card is visible to
    # the AI through the signal/recall channel instead of always auto-selected.
    catalog_pack_files = {item.get("file") for item in pack.get("card_catalog", [])}
    assert custom_card in catalog_pack_files
    assert original_card not in pack["knowledge_cards"] + pack["deferred_knowledge_cards"]
    assert custom_card not in pack["must_read"]
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_observability_ids_route_to_idor_without_becoming_idor_evidence(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Jaeger OpenTelemetry trace ID exposes order object identifier",
    )
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "knowledge/cards/api-idor.md" in all_cards
    assert "knowledge/cards/information-disclosure-source-config.md" in all_cards
    # Cards beyond the selection budget stay visible as signals, never hidden.
    assert "path-pattern-management-exposure" in recall_ids
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_opa_cedar_routes_to_existing_authz_cards_and_pdp_pep_gate(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="OPA Cedar authorization policy decision enforcement PDP PEP tenant",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "auth-access" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_broad_signed_trace_and_policy_words_do_not_trigger_api_authz_refinements(tmp_path, pack_store):
    cases = (
        ("signed payload", ("knowledge/cards/api-idor.md", "knowledge/cards/auth-access.md")),
        ("trace", ("knowledge/cards/api-idor.md",)),
        ("policy decision", ("knowledge/cards/api-idor.md", "knowledge/cards/auth-access.md")),
        ("cedar tree", ("knowledge/cards/api-idor.md", "knowledge/cards/auth-access.md")),
    )
    for focus, forbidden_cards in cases:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]



def test_missing_parameter_focus_routes_to_discovery_card(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/search/records",
        "https://api.target.com/forms/query?filter=",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="missing-param parameter-null")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "missing-parameter-discovery" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_path_pattern_focus_routes_to_management_exposure_card(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://www.target.com/app01/login.html",
        "https://www.target.com/app02/stats/records.json",
        "https://www.target.com/static/asset-manifest.json",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="path-pattern management-exposure")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "path-pattern-management-exposure" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_observed_api_path_routes_to_bounded_ancestor_prefix_cards(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="observed API path https://target.com/prod-api/system/user/list",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "path-pattern-management-exposure" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_generic_path_does_not_route_to_ancestor_prefix_discovery(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="generic path https://target.com/about/company",
    )
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]



def test_context_pack_surfaces_actor_matrix_gaps(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/accounts/42/export?account_id=42",
    ])
    _record_primary_context_evidence(
        pack_store, tmp_path, "owner-baseline",
        endpoint="https://api.target.com/api/accounts/42/export", family="IDOR",
        actor="owner", object_scope="own", variant="baseline",
    )

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="api-idor",
        coverage_state=([{
            "endpoint": "/api/accounts/42/export",
            "vuln_class": "IDOR",
        }], {}),
    )
    output = format_context_pack(pack)

    assert pack["source_summary"]["evidence_ledger_entries"] == 1
    assert pack["source_summary"]["evidence_source_kind"] == "store"
    assert pack["source_summary"]["evidence_source_status"] == "ready"
    assert pack["source_summary"]["actor_matrix_gaps"] > 0
    assert all("ledger.jsonl" not in item and "metadata.sqlite3" not in item for item in pack["must_read"])
    assert any("Actor gap" in item and "peer" in item for item in pack["evidence_anchors"])
    assert any("record-evidence" in item for item in pack["write_back"])
    assert "Actor matrix gaps:" in output


def test_context_pack_without_owner_backed_classes_keeps_context_but_no_actor_matrix(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/api/accounts/42?account_id=42"])

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="api-idor command injection payload family",
        coverage_state=([], {}),
    )

    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert pack["knowledge_cards"] == []  # selection retired; catalog is the surface
    assert pack["actor_matrix_gaps"] == []
    assert pack["source_summary"]["actor_matrix_gaps"] == 0
    assert not any("Actor gap:" in item for item in pack["evidence_anchors"])


def test_graphql_focus_routes_to_graphql_card(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/graphql"])

    pack = build_context_pack(tmp_path, target="target.com", focus="graphql")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "graphql" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_graphql_node_global_id_does_not_route_to_node_runtime_card(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="GraphQL private posts node global ID introspection query fields",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "graphql" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_sqli_focus_routes_to_hidden_surface_card(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/search?q=case",
        "https://api.target.com/api/internal/config",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="sqli hidden-param")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "sqli-hidden-surfaces" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_query_semantics_sqli_focus_keeps_visible_input_baseline(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SQL injection WHERE clause product category filter search sort pagination report export tenant scope hidden products",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "sqli-hidden-surfaces" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_api_price_mutation_focus_pairs_api_with_business_logic(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API testing unused endpoint product price PATCH method matrix buy checkout item",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "business-logic-state-machines" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_api_parameter_pollution_focus_routes_to_api_workflow(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API server-side parameter pollution HPP duplicate query parameter backend request reset password field truncation",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "missing-parameter-discovery" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_api_mass_assignment_focus_pairs_api_and_business_logic(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API mass assignment over-posting PATCH user profile role isAdmin plan status verified approved",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "business-logic-state-machines" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_upload_import_focus_routes_to_upload_parser(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/import/preview",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="upload import")

    assert "upload-parser" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_svg_upload_xxe_focus_keeps_conversion_readback_evidence(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SVG image upload avatar XML parser XXE external entity server image conversion read-back",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "upload-parser" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_upload_execution_focus_routes_to_deep_card(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/upload/avatar",
    ])

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="file upload web shell avatar content-type bypass executable extension server path",
    )

    assert "upload-to-execution" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "upload-to-execution" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_upload_execution_filename_path_traversal_keeps_storage_proof(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/my-account/avatar",
    ])

    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="file upload web shell path traversal filename encoded parent segment avatar read-back executable",
    )

    assert "upload-to-execution" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_rce_focus_routes_to_controlled_impact_card(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/template/render",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="rce command-injection ssti")

    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_os_command_injection_focus_surfaces_output_channel_baseline(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="OS command injection simple product stock checker raw output blind timing output redirection OAST",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_node_prototype_focus_routes_to_node_card(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/profile/preferences",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="node prototype-pollution")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "node-prototype-pollution" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_ranked_technology_stack_is_visible_without_bare_high_risk_routing(tmp_path, pack_store):
    ranked = {
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
        }
    ranked["target"] = "target.com"
    write_surface_projection(tmp_path, "target.com", ranked, manifest=build_surface_input_manifest(tmp_path, "target.com"))
    pack = build_context_pack(tmp_path, target="target.com")

    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]
    assert pack["tech_stack"] == ["Java", "PHP", "Spring"]
    assert "Tech stack: Java, PHP, Spring" in format_context_pack(pack)


def test_node_stack_plus_json_shape_routes_to_node_card(tmp_path, pack_store):
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

    # Tech-stack word-list routing degrades to signal visibility: the card is
    # AI-readable in recall instead of auto-selected.
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "node-prototype-pollution" in recall_ids


def test_wordpress_stack_routes_to_existing_inventory_card(tmp_path, pack_store):
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

    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "wordpress-surface-intelligence" in recall_ids


def test_explicit_focus_wins_over_mixed_background_signals(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://login.target.com/oauth/callback?code=abc&state=xyz",
        "https://api.target.com/.well-known/jwks.json",
        "https://api.target.com/api/profile/preferences",
        "https://api.target.com/api/import?url=https://example.com/feed",
    ])
    pack_store.set_active_goal(command_id="goal", goal="Validate synthetic target", actor="operator")
    for index, statement in enumerate(("OAuth account-linking lead", "Node Express lodash merge __proto__ lead")):
        _remember_hypothesis(pack_store, statement, command_id=f"lead-{index}")

    auth_pack = build_context_pack(tmp_path, target="target.com", focus="jwt oauth sso")
    node_pack = build_context_pack(tmp_path, target="target.com", focus="node prototype-pollution")

    assert "knowledge/cards/auth-sso-token-edge-cases.md" in [item.get("file") for item in auth_pack.get("card_catalog", [])]
    assert "knowledge/cards/node-prototype-pollution.md" in [item.get("file") for item in node_pack.get("card_catalog", [])]


def test_ssrf_internal_focus_routes_to_internal_impact_card(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/import?url=https://example.com/feed",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="ssrf-internal metadata")

    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_ssrf_localhost_admin_focus_routes_to_internal_impact(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SSRF stock check server-side fetch URL localhost admin internal system",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-url-fetch" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_ssrf_blacklist_filter_focus_surfaces_parser_boundary_seed(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SSRF blacklist input filter stockApi localhost loopback path encoding double encoding admin status change",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-url-fetch" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_internal_admin_without_fetch_context_does_not_load_ssrf_internal(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="internal admin panel access control management exposure",
    )

    # Word-list matches surface as signal annotations, not auto-selected cards.
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in recall_ids


def test_race_payment_focus_inherits_red_lines_from_claude(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/checkout/payment",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="race payment otp")

    assert "race-conditions" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "rules/red-lines.md" not in pack["required_checks"]


def test_candidate_finding_routes_to_triage_validation(tmp_path, pack_store):
    pack_store.create_finding(
        command_id="claim", finding_id="F-1", endpoint="https://target.com/api/org/123/users",
        method="GET", family="IDOR", title="Object access claim",
        claim="Compare org membership", actor="operator",
    )

    pack = build_context_pack(tmp_path, target="target.com")

    # S1 native loading: no skill recommendation; the owner fact "a candidate
    # awaits validation" now loads the reporting check directly (what the old
    # triage-validation recommendation encoded).
    assert "selected_skill" not in pack
    assert "skill_route" not in pack
    assert "rules/reporting.md" in pack["required_checks"]
    assert any("F-1" in item for item in pack["evidence_anchors"])


def test_explicit_focus_survives_when_recon_is_missing(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_sqli_focus_without_recon_routes_to_vuln_skill(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="sqli hidden-param")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "sqli-hidden-surfaces" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_nosql_focus_without_recon_routes_to_nosql_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="nosql operator-injection")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "nosql-query-injection" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_nosql_expression_focus_does_not_match_express_node(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="NoSQL MongoDB category filter string expression syntax error boolean pair",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "nosql-query-injection" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_xxe_focus_without_recon_routes_to_xml_parser_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="xxe xml-parser xinclude")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_xxe_error_reflection_focus_keeps_parser_evidence_gate(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XXE XML parser business field unexpected value reflected error external entity content-type application/xml",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_xxe_metadata_ssrf_focus_routes_to_parser_and_internal_impact(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XXE XML parser SSRF metadata IAM role credentials external entity reflected business field",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_xinclude_form_parameter_focus_mentions_assembled_xml_path(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XInclude form parameter assembled into server-side XML productId stock checker namespace file read",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_path_traversal_focus_without_recon_routes_to_file_read_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="path-traversal lfi file-read")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "path-traversal-file-read" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_ssti_focus_without_recon_routes_to_template_card(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="ssti template-injection reflected message ERB code context sandbox user-supplied object",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "server-side-template-injection" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_template_engine_focus_routes_to_ssti_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="erb ruby-template")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "server-side-template-injection" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_template_engine_context_focus_routes_to_ssti_not_node_runtime(tmp_path, pack_store):
    focuses = [
        "Tornado template preferred name code context user supplied object documentation",
        "Mako template expression code context render trigger",
        "Handlebars template server side render helper sandbox",
    ]

    for focus in focuses:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)

        assert "skill_route" not in pack and "selected_skill" not in pack
        assert "server-side-template-injection" in {item.get("id") for item in pack.get("card_catalog", [])}
        assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_deserialization_focus_without_recon_routes_to_deser_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="deserialization signed-object viewstate")

    assert "skill_route" not in pack and "selected_skill" not in pack
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "insecure-deserialization" in recall_ids
    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_serialized_session_cookie_deserialization_prioritizes_integrity_and_state_tamper(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="insecure deserialization serialized session cookie base64 object admin role privilege escalation",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "insecure-deserialization" in recall_ids
    # 静态 seeds 已退役：判断限定在卡片正文中（insecure-deserialization.md）。
    assert pack["hypothesis_seeds"] == []


def test_deserialization_type_and_application_gadget_focus_keeps_minimal_evidence_gate(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="deserialization serialized data types boolean string integer application functionality gadget delete file avatar object",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "insecure-deserialization" in recall_ids


def test_explicit_browser_boundary_focus_without_recon_routes_to_client_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="cors csrf clickjacking dom-xss postmessage")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "browser-client-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_cors_origin_credentials_focus_does_not_route_to_auth_access(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="CORS trusted origin null origin credentialed read Access-Control-Allow-Credentials",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "browser-client-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_dom_navigation_focus_routes_to_browser_boundary_card(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="open-redirect client-side-redirect cookie-manipulation dom-clobbering",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "browser-client-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_explicit_proxy_cache_focus_without_recon_routes_to_proxy_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="host-header request-smuggling web-cache-poisoning cache-deception")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "proxy-cache-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_websocket_focus_without_recon_routes_to_realtime_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="websocket cswsh")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "websocket-realtime-api" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_websocket_cswsh_authz_origin_focus_does_not_route_to_idor(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="WebSockets cross-site websocket hijacking CSWSH origin message schema authz",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "websocket-realtime-api" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_information_disclosure_focus_without_recon_routes_to_info_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="information-disclosure source-map debug")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "information-disclosure-source-config" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_information_disclosure_stack_trace_focus_does_not_route_to_race(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Information disclosure source map backup file debug stack trace config leak",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "information-disclosure-source-config" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_xss_focus_without_recon_routes_to_xss_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="xss reflected-xss stored-xss")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "xss-client-injection" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join
    # required_checks is now a fixed skill-based set; per-focus exclusion
    # assertions are retired with the word-list check router.


def test_explicit_csp_focus_without_recon_routes_to_xss_and_browser_cards(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="csp content-security-policy sandbox-escape dangling-markup")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "xss-client-injection" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "browser-client-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_explicit_api_testing_focus_without_recon_routes_to_api_workflow(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="api testing rest-api openapi")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_business_logic_focus_without_recon_routes_to_logic_card(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="business logic state-machine client-side-controls price-tamper",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "business-logic-state-machines" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_password_reset_focus_without_recon_routes_to_auth_recovery_card(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="password reset broken-logic username-enumeration credential-attack mfa",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "auth-credential-recovery-flows" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_web_llm_focus_without_recon_routes_to_llm_card(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="web-llm prompt-injection rag")

    assert "skill_route" not in pack and "selected_skill" not in pack
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "web-llm-tool-chains" in recall_ids  # exact-list retired: state cards may join


def test_agent_lifecycle_signals_route_to_web_llm_card(tmp_path, pack_store):
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
        assert "skill_route" not in pack and "selected_skill" not in pack, signal
        assert "web-llm-tool-chains" in {item.get("id") for item in pack.get("card_catalog", [])}, signal
        assert "rules/playbook-router.md" in pack["required_checks"], signal


def test_target_memory_agent_signal_routes_without_explicit_focus(tmp_path, pack_store):
    _remember_hypothesis(pack_store, "Observed cross-session memory propagation between agents")

    pack = build_context_pack(tmp_path, target="target.com")

    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "web-llm-tool-chains" in recall_ids


def test_broad_agent_signal_words_do_not_route_to_web_llm_card(tmp_path, pack_store):
    for focus in (
        "OpenAPI schema drift",
        "database server schema drift",
        "crypto rug pull",
        "session memory cache",
        "shadow DOM component",
    ):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert "knowledge/cards/web-llm-tool-chains.md" not in pack["knowledge_cards"], focus


def test_unprotected_admin_access_control_prioritizes_auth_access(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Unprotected admin functionality unprotected admin panel delete user administrator-panel access control",
    )

    assert "skill_route" not in pack and "selected_skill" not in pack
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in recall_ids
    assert "path-pattern-management-exposure" in recall_ids


def test_explicit_ssrf_internal_focus_without_recon_routes_to_vuln_skill(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="ssrf-internal metadata")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-url-fetch" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_oauth_focus_without_recon_routes_to_vuln_skill(tmp_path, pack_store):
    pack = build_context_pack(tmp_path, target="target.com", focus="oauth sso token-binding account-linking")

    assert "skill_route" not in pack and "selected_skill" not in pack
    assert "auth-sso-token-edge-cases" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_unverified_negative_note_remains_advisory_with_new_surface(tmp_path, pack_store):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/graphql"])
    pack_store.remember(
        command_id="note", kind="note", statement="GraphQL introspection reportedly disabled",
        conditions="Unverified operator note; execution evidence unavailable",
        reopen_when="New operation names or session", next_intent="Inspect GraphQL surface",
        evidence=[], actor="operator",
    )
    pack = build_context_pack(tmp_path, target="target.com", focus="graphql")
    assert pack["target_experiences"]["items"][0]["kind"] == "note"
    assert pack["source_summary"]["evidence_ledger_entries"] == 0
    assert "New operation names or session" in format_context_pack(pack)



def test_distilled_knowledge_cards_route_from_explicit_focus_without_recon(tmp_path, pack_store):
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
        assert expected_card in [item.get("file") for item in pack.get("card_catalog", [])]


def test_json_view_differential_routing_is_precise_and_budgeted(tmp_path, pack_store):
    collision = build_context_pack(
        tmp_path,
        target="target.com",
        focus="validate-proxy duplicate JSON key scalar array object first key last key",
    )
    assert "view-differential" in {item.get("id") for item in collision.get("card_catalog", [])}
    assert "type-confusion-controlflow" in {item.get("id") for item in collision.get("card_catalog", [])}

    ordinary = build_context_pack(
        tmp_path,
        target="target.com",
        focus="ordinary JSON API response schema",
    )

    ordinary_role = build_context_pack(
        tmp_path,
        target="target.com",
        focus="ordinary JSON API profile response includes a role field",
    )

    pretest = build_context_pack(
        tmp_path,
        target="target.com",
        focus="可写 JSON 角色字段先存储，再由权限 API 和管理 API 读取",
    )
    assert "view-differential" in {item.get("id") for item in pretest.get("card_catalog", [])}

    stored = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Validate-Store superadmin unpaired surrogate JSON parser",
    )
    assert "view-differential" in {item.get("id") for item in stored.get("card_catalog", [])}

    raw_surrogate = build_context_pack(
        tmp_path,
        target="target.com",
        focus=r'匿名提交 {"role":"superadmin\ud888"} 后 Admin API 截断并授予权限',
    )
    assert "view-differential" in {item.get("id") for item in raw_surrogate.get("card_catalog", [])}

    valid_surrogate_pair = build_context_pack(
        tmp_path,
        target="target.com",
        focus=r'普通 JSON 昵称 {"name":"user\ud83d\ude00"}',
    )
    assert "knowledge/cards/view-differential.md" not in (
        valid_surrogate_pair["knowledge_cards"]
        + valid_surrogate_pair["deferred_knowledge_cards"]
    )


def test_public_package_history_routes_to_bounded_recon_intelligence(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="npm package history published artifact",
    )

    assert "selected_skill" not in pack and "skill_route" not in pack
    assert "public-package-artifact-intelligence" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_container_image_history_routes_to_public_artifact_card(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="GHCR container image history and layer versions",
    )

    assert "selected_skill" not in pack and "skill_route" not in pack
    assert "public-package-artifact-intelligence" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_dependency_confusion_keeps_ci_cd_and_artifact_cards(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="dependency confusion npm public registry package history",
    )

    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]
    assert "knowledge/cards/public-package-artifact-intelligence.md" in all_cards
    assert "knowledge/cards/cicd-trust-boundaries.md" in all_cards


def test_bare_package_build_and_image_do_not_route_to_public_artifact_card(tmp_path, pack_store):
    for focus in ("package", "build", "image"):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]



def test_js_runtime_signature_signals_route_to_bounded_recon_branch(tmp_path, pack_store):
    signals = (
        "js reverse request chain",
        "frontend signature reconstruction",
        "request initiator and local JS rebuild",
        "browser runtime hook for encrypted parameter",
        "first divergence in client request generation",
    )

    for focus in signals:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert "selected_skill" not in pack and "skill_route" not in pack, focus
        assert pack["knowledge_cards"] == [], focus


def test_js_runtime_signature_broad_words_do_not_route_new_card(tmp_path, pack_store):
    for focus in (
        "signature",
        "encryption",
        "hook",
        "browser " + ("x" * 121) + " runtime hook",
    ):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]


def test_custom_protocol_signals_route_to_bounded_recon_branch(tmp_path, pack_store):
    signals = (
        "custom binary protocol frame recovery",
        "protocol reverse and message dictionary",
        "PCAP framing with opcode and checksum",
        "MessagePack length prefix and state recovery",
        "private RPC TLV endian field",
    )

    for focus in signals:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
        assert "selected_skill" not in pack and "skill_route" not in pack, focus
        assert pack["knowledge_cards"] == [], focus


def test_custom_protocol_broad_words_do_not_route_new_card(tmp_path, pack_store):
    for focus in (
        "pcap",
        "protobuf",
        "state machine",
        "handshake",
        "pcap " + ("x" * 121) + " opcode",
    ):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]


def test_custom_protocol_keeps_grpc_and_websocket_specialized_cards(tmp_path, pack_store):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="custom binary protocol frame layout with gRPC protobuf and WebSocket",
    )

    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]
    assert "knowledge/cards/custom-protocol-state-recovery.md" in all_cards
    assert "knowledge/cards/grpc-api-boundaries.md" in all_cards
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "websocket-realtime-api" in recall_ids


def test_target_memory_runtime_signal_routes_without_explicit_focus(tmp_path, pack_store):
    _remember_hypothesis(pack_store, "request initiator captured; local JS rebuild pending")

    pack = build_context_pack(tmp_path, target="target.com")

    assert "skill_route" not in pack and "selected_skill" not in pack
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "js-runtime-signature-reconstruction" in recall_ids


def test_context_pack_recovers_advisory_notes_with_conditions_and_source(tmp_path, pack_store):
    statements = {
        "cdn-filtering-502": "CDN may filter backend responses: compare 502 with 404",
        "wildcard-dns": "random123.target.com resolves to the same CDN",
    }
    for entry_id, statement in statements.items():
        pack_store.remember(
            command_id=entry_id, kind="note", statement=statement,
            conditions="Operator observation; not yet validated", reopen_when="DNS or CDN changes",
            next_intent="Compare baseline", evidence=[], actor="operator",
        )
    before = pack_store.binding()
    pack = build_context_pack(tmp_path, target="target.com", focus="cdn")
    entries = {item["entry_id"]: item for item in pack["target_experiences"]["items"]}
    assert set(entries) == set(statements)
    assert pack["facts"] == []
    output = format_context_pack(pack)
    for entry_id, statement in statements.items():
        assert entries[entry_id]["kind"] == "note"
        assert statement in output
        assert pack_store.experience(entry_id)["recorded_by"] == "operator"
    assert "Operator observation; not yet validated" in output
    assert "DNS or CDN changes" in output
    assert pack_store.binding() == before


def test_write_back_commands_keep_root_and_negative_requirements(tmp_path):
    root = tmp_path / "root with spaces"
    store = TargetStore(root, "target.com")
    store.initialize()
    _record_primary_context_evidence(store, root, "negative")
    operation_id = store.page("operations")["items"][0]["id"]
    pack = build_context_pack(root, target=store.target)
    for command in pack["write_back"][:4]:
        argv = shlex.split(command.replace("OPERATION_ID", operation_id))
        assert argv[argv.index("--repo-root") + 1] == str(root)
        result = subprocess.run([*argv, "--json"], capture_output=True, text=True, check=True)
        assert json.loads(result.stdout)["receipt"]["entity_id"]
    experiences = store.experience_page()["items"]
    assert sorted(item["kind"] for item in experiences) == ["handoff", "handoff", "hypothesis", "negative"]
    negative = next(item for item in experiences if item["kind"] == "negative")
    assert negative["conditions"] == "CONDITIONS"
    assert negative["reopen_when"] == "REOPEN_WHEN"
    assert negative["evidence"] == [{"operation_id": operation_id, "step": 0}]
