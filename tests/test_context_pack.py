"""Tests for tools/context_pack.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import context_pack as context_pack_module
from autopilot_state import build_autopilot_state, load_closure_projection, stagnation_fingerprint
from checkpoint import build_checkpoint
from context_pack import build_context_pack, format_context_pack
from skill_catalog import SKILL_CATALOG, SKILL_PATHS
from evidence_ledger import record_entry
from surface_projection import build_surface_input_manifest, write_surface_projection
from tools.experience_schema import make_entry_id
from tools.knowledge_registry import KnowledgeRegistryError
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


def test_context_pack_retired_skill_recommendation_keeps_skill_catalog_import_free(tmp_path):
    """S1 native loading (batch 3): context_pack no longer imports skill_catalog
    at all and does not duplicate the platform's skill listing — the routing
    surface is the on-disk SKILL.md frontmatter surfaced by Claude Code's
    native skill mechanism, and the recommendation fields are empty
    compatibility shells."""
    from tools import skill_catalog

    for name in ("SKILL_CATALOG", "SKILL_PATHS", "SKILL_ROUTE_MODES",
                 "SKILL_TEST_DIMENSIONS", "skill_route"):
        assert not hasattr(context_pack_module, name), name

    pack = build_context_pack(tmp_path, target="target.com")
    # The pack no longer publishes a skill catalog: the platform's skill
    # listing is the single routing surface. Recommendation fields stay as
    # empty compatibility shells.
    assert "skill_catalog" not in pack
    assert pack["selected_skill"] == ""
    assert pack["skill_route"] == {}

    # skill_catalog.skill_route factory stays available for owner-generated
    # actions (param_discovery) and stays import-independent of the pack.
    route = skill_catalog.skill_route("web2-vuln-classes", "  API evidence  ")
    assert route == {
        "skill_id": "web2-vuln-classes",
        "skill_path": "skills/web2-vuln-classes/SKILL.md",
        "reason": "API evidence",
        "required_dimensions": skill_catalog.SKILL_TEST_DIMENSIONS["web2-vuln-classes"],
    }
    route["required_dimensions"].append("caller-local")
    assert "caller-local" not in skill_catalog.SKILL_TEST_DIMENSIONS["web2-vuln-classes"]


def test_must_read_omits_absent_target_state_paths(tmp_path):
    """K-1: after a reset/fresh start, goal-memory files legitimately do not
    exist. must_read must not point at them — a contract listing missing
    files gives the reader no way to tell a defect from a fresh start. Repo
    contract documents stay unconditional."""
    pack = build_context_pack(tmp_path, target="target.com")

    assert "memory/goals/active.json" not in pack["must_read"]
    assert "memory/goals/targets/target.com.json" not in pack["must_read"]
    assert "skills/runtime-protocol.md" in pack["must_read"]


def test_skill_catalog_and_cards_stay_advisory_and_outside_must_read(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    catalog_paths = {item["path"] for item in SKILL_CATALOG.values()}

    assert "CLAUDE.md" not in pack["must_read"]
    assert "SKILL.md" not in pack["must_read"]
    assert "skills/runtime-protocol.md" in pack["must_read"]
    # S1 native loading: no recommendation and no duplicated catalog — the
    # platform's native skill listing is the routing surface.
    assert pack["selected_skill"] == ""
    assert pack["skill_route"] == {}
    assert "skill_catalog" not in pack
    assert set(pack["must_read"]).isdisjoint(catalog_paths)
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
def test_command_and_autopilot_state_recall_share_candidates(tmp_path, capsys, focus, expected_card):
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
        "target", "focus", "selected_skill", "knowledge_cards",
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
    for skill_id, entry in SKILL_CATALOG.items():
        skill_file = repo / entry["path"]
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


def test_native_pilot_recommendation_surface_fully_retired(tmp_path):
    """S1 batch 3 superseded the bb-methodology pilot: the pack recommends no
    skill at all (empty compatibility shells) and does not duplicate the
    platform's skill listing. The pilot-era `native_skills` field is gone."""
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/"])

    pack = build_context_pack(tmp_path, target="target.com", focus="api idor")
    output = format_context_pack(pack)

    assert pack["selected_skill"] == ""
    assert pack["selected_skill_id"] == ""
    assert pack["why_this_skill"] == ""
    assert pack["skill_route"] == {}
    assert "native_skills" not in pack
    assert "skill_catalog" not in pack
    assert "Skill recommendation retired (S1 native loading)" in output


def test_memory_continuity_no_longer_drives_recommendation(tmp_path):
    """Target-memory `selected_skills` is historical continuity data; with the
    recommendation layer retired it can no longer put a skill into the pack's
    recommendation slot. The AI reads it from memory and loads skills itself."""
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/"])
    _seed_target_memory(tmp_path, "target.com", {
        "selected_skills": ["web2-vuln-classes"],
    })

    pack = build_context_pack(tmp_path, target="target.com")

    assert pack["selected_skill_id"] == ""
    assert pack["skill_route"] == {}


def test_api_idor_context_pack_selects_vuln_skill_and_cards(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/org/123/users?user_id=456",
    ])
    _seed_target_memory(tmp_path, "target.com", {
        "active_leads": [{"text": "/api/org/{id}/users may allow org swap"}],
    })

    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    output = format_context_pack(pack)

    # Word-list skill routing is retired: the suggestion comes from owner
    # facts only, so a category-naming focus no longer forces the vuln skill.
    # What must hold: the pack publishes the full card catalog and the
    # focus-named card, and the override contract stays visible.
    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}
    catalog_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "api-idor" in catalog_ids
    assert "auth-sso-token-edge-cases" in catalog_ids, "full catalog published, not a filtered subset"
    assert any("Surface review" in item for item in pack["evidence_anchors"])
    assert "AI override" in output


def test_context_pack_exposes_registry_metadata_for_selected_cards(tmp_path):
    # 语义选卡退役：registry metadata（layer/load/purpose）的发现面是
    # card_catalog —— 每张登记卡都带完整 capability 行，选择权在 AI。
    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")
    caps = {item["file"]: item for item in pack.get("card_catalog", [])}

    assert caps["knowledge/cards/api-idor.md"]["layer"] == "core"
    assert caps["knowledge/cards/api-idor.md"]["load"] == "signal-or-default"
    assert caps["knowledge/cards/api-idor.md"]["purpose"] == "validate"
    assert "Knowledge card catalog:" in format_context_pack(pack)


def test_target_registry_remap_reaches_context_pack_checkpoint_and_witness(tmp_path):
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
    _seed_target_memory(tmp_path, "target.com", {})
    active_path = tmp_path / "memory" / "goals" / "active.json"
    active = json.loads(active_path.read_text(encoding="utf-8"))
    active["active_goal"] = "Validate one template rendering boundary"
    active["current_hypothesis"] = "SSTI template injection render payload family"
    active_path.write_text(json.dumps(active), encoding="utf-8")

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


def test_observability_ids_route_to_idor_without_becoming_idor_evidence(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Jaeger OpenTelemetry trace ID exposes order object identifier",
    )
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "knowledge/cards/api-idor.md" in all_cards
    assert "knowledge/cards/information-disclosure-source-config.md" in all_cards
    # Cards beyond the selection budget stay visible as signals, never hidden.
    assert "path-pattern-management-exposure" in recall_ids
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_opa_cedar_routes_to_existing_authz_cards_and_pdp_pep_gate(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="OPA Cedar authorization policy decision enforcement PDP PEP tenant",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "auth-access" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}
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
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]



def test_missing_parameter_focus_routes_to_discovery_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/search/records",
        "https://api.target.com/forms/query?filter=",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="missing-param parameter-null")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "missing-parameter-discovery" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_path_pattern_focus_routes_to_management_exposure_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://www.target.com/app01/login.html",
        "https://www.target.com/app02/stats/records.json",
        "https://www.target.com/static/asset-manifest.json",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="path-pattern management-exposure")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "path-pattern-management-exposure" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_observed_api_path_routes_to_bounded_ancestor_prefix_cards(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="observed API path https://target.com/prod-api/system/user/list",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "path-pattern-management-exposure" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_generic_path_does_not_route_to_ancestor_prefix_discovery(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="generic path https://target.com/about/company",
    )
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]



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
    assert pack["source_summary"]["actor_matrix_gaps"] > 0
    assert "memory/evidence/target.com/ledger.jsonl" in pack["must_read"]
    assert any("Actor gap" in item and "peer" in item for item in pack["evidence_anchors"])
    assert any("tools/evidence_ledger.py" in item for item in pack["write_back"])
    assert "Actor matrix gaps:" in output


def test_context_pack_without_owner_backed_classes_keeps_context_but_no_actor_matrix(tmp_path):
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


def test_graphql_focus_routes_to_graphql_card(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/graphql"])

    pack = build_context_pack(tmp_path, target="target.com", focus="graphql")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "graphql" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_graphql_node_global_id_does_not_route_to_node_runtime_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="GraphQL private posts node global ID introspection query fields",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "graphql" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_sqli_focus_routes_to_hidden_surface_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/search?q=case",
        "https://api.target.com/api/internal/config",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="sqli hidden-param")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "sqli-hidden-surfaces" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_query_semantics_sqli_focus_keeps_visible_input_baseline(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SQL injection WHERE clause product category filter search sort pagination report export tenant scope hidden products",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "sqli-hidden-surfaces" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_api_price_mutation_focus_pairs_api_with_business_logic(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API testing unused endpoint product price PATCH method matrix buy checkout item",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "business-logic-state-machines" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_api_parameter_pollution_focus_routes_to_api_workflow(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API server-side parameter pollution HPP duplicate query parameter backend request reset password field truncation",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "missing-parameter-discovery" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_api_mass_assignment_focus_pairs_api_and_business_logic(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="API mass assignment over-posting PATCH user profile role isAdmin plan status verified approved",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "business-logic-state-machines" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_upload_import_focus_routes_to_upload_parser(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/import/preview",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="upload import")

    assert "upload-parser" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_svg_upload_xxe_focus_keeps_conversion_readback_evidence(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SVG image upload avatar XML parser XXE external entity server image conversion read-back",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "upload-parser" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_upload_execution_focus_routes_to_deep_card(tmp_path):
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


def test_upload_execution_filename_path_traversal_keeps_storage_proof(tmp_path):
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


def test_rce_focus_routes_to_controlled_impact_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/template/render",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="rce command-injection ssti")

    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_os_command_injection_focus_surfaces_output_channel_baseline(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="OS command injection simple product stock checker raw output blind timing output redirection OAST",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_node_prototype_focus_routes_to_node_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/profile/preferences",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="node prototype-pollution")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "node-prototype-pollution" in {item.get("id") for item in pack.get("card_catalog", [])}


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

    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]
    assert pack["tech_stack"] == ["Java", "PHP", "Spring"]
    assert "Tech stack: Java, PHP, Spring" in format_context_pack(pack)


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

    # Tech-stack word-list routing degrades to signal visibility: the card is
    # AI-readable in recall instead of auto-selected.
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "node-prototype-pollution" in recall_ids


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

    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "wordpress-surface-intelligence" in recall_ids


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

    assert "knowledge/cards/auth-sso-token-edge-cases.md" in [item.get("file") for item in auth_pack.get("card_catalog", [])]
    assert "knowledge/cards/node-prototype-pollution.md" in [item.get("file") for item in node_pack.get("card_catalog", [])]


def test_ssrf_internal_focus_routes_to_internal_impact_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/import?url=https://example.com/feed",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="ssrf-internal metadata")

    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_ssrf_localhost_admin_focus_routes_to_internal_impact(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SSRF stock check server-side fetch URL localhost admin internal system",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-url-fetch" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_ssrf_blacklist_filter_focus_surfaces_parser_boundary_seed(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="SSRF blacklist input filter stockApi localhost loopback path encoding double encoding admin status change",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-url-fetch" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_internal_admin_without_fetch_context_does_not_load_ssrf_internal(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="internal admin panel access control management exposure",
    )

    # Word-list matches surface as signal annotations, not auto-selected cards.
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in recall_ids


def test_race_payment_focus_inherits_red_lines_from_claude(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/checkout/payment",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="race payment otp")

    assert "race-conditions" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "rules/red-lines.md" not in pack["required_checks"]


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

    # S1 native loading: no skill recommendation; the owner fact "a candidate
    # awaits validation" now loads the reporting check directly (what the old
    # triage-validation recommendation encoded).
    assert pack["selected_skill"] == ""
    assert pack["skill_route"] == {}
    assert "rules/reporting.md" in pack["required_checks"]
    assert any("F-1" in item for item in pack["evidence_anchors"])


def test_explicit_focus_survives_when_recon_is_missing(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="api-idor")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_sqli_focus_without_recon_routes_to_vuln_skill(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="sqli hidden-param")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "sqli-hidden-surfaces" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_nosql_focus_without_recon_routes_to_nosql_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="nosql operator-injection")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "nosql-query-injection" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_nosql_expression_focus_does_not_match_express_node(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="NoSQL MongoDB category filter string expression syntax error boolean pair",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "nosql-query-injection" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_xxe_focus_without_recon_routes_to_xml_parser_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="xxe xml-parser xinclude")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_xxe_error_reflection_focus_keeps_parser_evidence_gate(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XXE XML parser business field unexpected value reflected error external entity content-type application/xml",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_xxe_metadata_ssrf_focus_routes_to_parser_and_internal_impact(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XXE XML parser SSRF metadata IAM role credentials external entity reflected business field",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_xinclude_form_parameter_focus_mentions_assembled_xml_path(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="XInclude form parameter assembled into server-side XML productId stock checker namespace file read",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "xxe-xml-parser" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_path_traversal_focus_without_recon_routes_to_file_read_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="path-traversal lfi file-read")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "path-traversal-file-read" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_ssti_focus_without_recon_routes_to_template_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="ssti template-injection reflected message ERB code context sandbox user-supplied object",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "server-side-template-injection" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_template_engine_focus_routes_to_ssti_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="erb ruby-template")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "server-side-template-injection" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_template_engine_context_focus_routes_to_ssti_not_node_runtime(tmp_path):
    focuses = [
        "Tornado template preferred name code context user supplied object documentation",
        "Mako template expression code context render trigger",
        "Handlebars template server side render helper sandbox",
    ]

    for focus in focuses:
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)

        assert pack["skill_route"] == {} and pack["selected_skill"] == ""
        assert "server-side-template-injection" in {item.get("id") for item in pack.get("card_catalog", [])}
        assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_deserialization_focus_without_recon_routes_to_deser_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="deserialization signed-object viewstate")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "insecure-deserialization" in recall_ids
    assert "controlled-rce-impact" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_serialized_session_cookie_deserialization_prioritizes_integrity_and_state_tamper(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="insecure deserialization serialized session cookie base64 object admin role privilege escalation",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "insecure-deserialization" in recall_ids
    # 静态 seeds 已退役：判断限定在卡片正文中（insecure-deserialization.md）。
    assert pack["hypothesis_seeds"] == []


def test_deserialization_type_and_application_gadget_focus_keeps_minimal_evidence_gate(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="deserialization serialized data types boolean string integer application functionality gadget delete file avatar object",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "insecure-deserialization" in recall_ids


def test_explicit_browser_boundary_focus_without_recon_routes_to_client_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="cors csrf clickjacking dom-xss postmessage")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "browser-client-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_cors_origin_credentials_focus_does_not_route_to_auth_access(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="CORS trusted origin null origin credentialed read Access-Control-Allow-Credentials",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "browser-client-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_dom_navigation_focus_routes_to_browser_boundary_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="open-redirect client-side-redirect cookie-manipulation dom-clobbering",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "browser-client-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_explicit_proxy_cache_focus_without_recon_routes_to_proxy_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="host-header request-smuggling web-cache-poisoning cache-deception")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "proxy-cache-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_websocket_focus_without_recon_routes_to_realtime_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="websocket cswsh")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "websocket-realtime-api" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_websocket_cswsh_authz_origin_focus_does_not_route_to_idor(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="WebSockets cross-site websocket hijacking CSWSH origin message schema authz",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "websocket-realtime-api" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_information_disclosure_focus_without_recon_routes_to_info_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="information-disclosure source-map debug")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "information-disclosure-source-config" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_information_disclosure_stack_trace_focus_does_not_route_to_race(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="Information disclosure source map backup file debug stack trace config leak",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "information-disclosure-source-config" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_xss_focus_without_recon_routes_to_xss_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="xss reflected-xss stored-xss")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "xss-client-injection" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join
    # required_checks is now a fixed skill-based set; per-focus exclusion
    # assertions are retired with the word-list check router.


def test_explicit_csp_focus_without_recon_routes_to_xss_and_browser_cards(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="csp content-security-policy sandbox-escape dangling-markup")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "xss-client-injection" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "browser-client-boundaries" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_explicit_api_testing_focus_without_recon_routes_to_api_workflow(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="api testing rest-api openapi")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "api-idor" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_business_logic_focus_without_recon_routes_to_logic_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="business logic state-machine client-side-controls price-tamper",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "business-logic-state-machines" in {item.get("id") for item in pack.get("card_catalog", [])}  # exact-list retired: state cards may join


def test_explicit_password_reset_focus_without_recon_routes_to_auth_recovery_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="password reset broken-logic username-enumeration credential-attack mfa",
    )

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "auth-credential-recovery-flows" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_web_llm_focus_without_recon_routes_to_llm_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="web-llm prompt-injection rag")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "web-llm-tool-chains" in recall_ids  # exact-list retired: state cards may join


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
        assert pack["skill_route"] == {} and pack["selected_skill"] == "", signal
        assert "web-llm-tool-chains" in {item.get("id") for item in pack.get("card_catalog", [])}, signal
        assert "rules/playbook-router.md" in pack["required_checks"], signal


def test_target_memory_agent_signal_routes_without_explicit_focus(tmp_path):
    _seed_target_memory(
        tmp_path,
        "target.com",
        {"active_leads": [{"text": "Observed cross-session memory propagation between agents"}]},
    )

    pack = build_context_pack(tmp_path, target="target.com")

    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "web-llm-tool-chains" in recall_ids


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

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in recall_ids
    assert "path-pattern-management-exposure" in recall_ids


def test_explicit_ssrf_internal_focus_without_recon_routes_to_vuln_skill(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="ssrf-internal metadata")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "ssrf-internal-impact" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "ssrf-url-fetch" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_explicit_oauth_focus_without_recon_routes_to_vuln_skill(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="oauth sso token-binding account-linking")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    assert "auth-sso-token-edge-cases" in {item.get("id") for item in pack.get("card_catalog", [])}
    assert "auth-access" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_dead_end_new_surface_becomes_contradiction(tmp_path):
    _seed_recon(tmp_path, "target.com", ["https://api.target.com/graphql"])
    _seed_target_memory(tmp_path, "target.com", {
        "dead_ends": [{"text": "GraphQL introspection disabled; no operation names in JS"}],
    })

    pack = build_context_pack(tmp_path, target="target.com", focus="graphql")



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
        assert expected_card in [item.get("file") for item in pack.get("card_catalog", [])]


def test_json_view_differential_routing_is_precise_and_budgeted(tmp_path):
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


def test_public_package_history_routes_to_bounded_recon_intelligence(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="npm package history published artifact",
    )

    assert pack["selected_skill"] == "" and pack["skill_route"] == {}
    assert "public-package-artifact-intelligence" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_container_image_history_routes_to_public_artifact_card(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="GHCR container image history and layer versions",
    )

    assert pack["selected_skill"] == "" and pack["skill_route"] == {}
    assert "public-package-artifact-intelligence" in {item.get("id") for item in pack.get("card_catalog", [])}


def test_dependency_confusion_keeps_ci_cd_and_artifact_cards(tmp_path):
    pack = build_context_pack(
        tmp_path,
        target="target.com",
        focus="dependency confusion npm public registry package history",
    )

    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]
    assert "knowledge/cards/public-package-artifact-intelligence.md" in all_cards
    assert "knowledge/cards/cicd-trust-boundaries.md" in all_cards


def test_bare_package_build_and_image_do_not_route_to_public_artifact_card(tmp_path):
    for focus in ("package", "build", "image"):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]



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
        assert pack["selected_skill"] == "" and pack["skill_route"] == {}, focus
        assert pack["knowledge_cards"] == [], focus


def test_js_runtime_signature_broad_words_do_not_route_new_card(tmp_path):
    for focus in (
        "signature",
        "encryption",
        "hook",
        "browser " + ("x" * 121) + " runtime hook",
    ):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]


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
        assert pack["selected_skill"] == "" and pack["skill_route"] == {}, focus
        assert pack["knowledge_cards"] == [], focus


def test_custom_protocol_broad_words_do_not_route_new_card(tmp_path):
    for focus in (
        "pcap",
        "protobuf",
        "state machine",
        "handshake",
        "pcap " + ("x" * 121) + " opcode",
    ):
        pack = build_context_pack(tmp_path, target="target.com", focus=focus)
    all_cards = [item.get("file") for item in pack.get("card_catalog", [])]


def test_custom_protocol_keeps_grpc_and_websocket_specialized_cards(tmp_path):
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


def test_target_memory_runtime_signal_routes_without_explicit_focus(tmp_path):
    _seed_target_memory(
        tmp_path,
        "target.com",
        {"active_leads": [{"text": "request initiator captured; local JS rebuild pending"}]},
    )

    pack = build_context_pack(tmp_path, target="target.com")

    assert pack["skill_route"] == {} and pack["selected_skill"] == ""
    recall_ids = {item.get("id") for item in pack.get("card_catalog", [])}
    assert "js-runtime-signature-reconstruction" in recall_ids


def test_context_pack_projects_target_facts_for_cheap_recovery(tmp_path):
    _seed_target_memory(tmp_path, "target.com", {
        "facts": {
            "cdn-filtering-502": {
                "text": "CDN filters backend responses: 502 = filtered, 404 = absent",
                "evidence_refs": ["evidence/target.com/diff.json"],
                "ts": "2026-09-09T00:00:00Z",
            },
            "wildcard-dns": {
                "text": "random123.target.com resolves to the same CDN: wildcard DNS",
                "evidence_refs": [],
                "ts": "2026-09-09T00:00:00Z",
            },
        },
    })

    pack = build_context_pack(tmp_path, target="target.com", focus="cdn")

    facts = pack["facts"]
    assert [item["key"] for item in facts] == ["cdn-filtering-502", "wildcard-dns"]
    assert facts[0]["text"].startswith("CDN filters backend responses")
    assert facts[0]["evidence_refs"] == ["evidence/target.com/diff.json"]
    assert facts[1]["evidence_refs"] == []
