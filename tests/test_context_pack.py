"""Tests for tools/context_pack.py."""

from __future__ import annotations

import json
from pathlib import Path

from context_pack import build_context_pack, format_context_pack
from evidence_ledger import record_entry


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
    assert "knowledge/cards/api-idor.md" in pack["knowledge_cards"]
    assert "knowledge/cards/auth-access.md" in pack["knowledge_cards"]
    assert any("P1/P2" in item for item in pack["evidence_anchors"])
    assert "AI override" in output


def test_auth_hidden_focus_routes_to_hidden_switch_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://manage.target.com/api/login",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="auth-hidden login-bypass")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/auth-hidden-switches.md"
    assert "knowledge/cards/auth-access.md" in pack["knowledge_cards"]
    assert any("隐藏认证参数" in seed or "自有或测试账号" in seed for seed in pack["hypothesis_seeds"])


def test_missing_parameter_focus_routes_to_discovery_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/orgapi/selectuser",
        "https://api.target.com/orgapi/..;/v3/api-docs",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="missing-param parameter-null")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/missing-parameter-discovery.md"
    assert any(
        "parameter is null" in seed or "目标特定参数词表" in seed
        for seed in pack["hypothesis_seeds"]
    )
    assert any("批量枚举真实 PII" in seed for seed in pack["hypothesis_seeds"])


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


def test_sqli_focus_routes_to_hidden_surface_card(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/search?q=case",
        "https://api.target.com/api/internal/config",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="sqli hidden-param")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"][0] == "knowledge/cards/sqli-hidden-surfaces.md"
    assert any("Header" in seed or "隐藏参数" in seed for seed in pack["hypothesis_seeds"])


def test_upload_import_focus_routes_to_upload_parser(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/import/preview",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="upload import")

    assert "knowledge/cards/upload-parser.md" in pack["knowledge_cards"]
    assert any("解析器" in seed for seed in pack["hypothesis_seeds"])


def test_race_payment_focus_keeps_red_lines_loaded(tmp_path):
    _seed_recon(tmp_path, "target.com", [
        "https://api.target.com/api/checkout/payment",
    ])

    pack = build_context_pack(tmp_path, target="target.com", focus="race payment otp")

    assert "knowledge/cards/race-conditions.md" in pack["knowledge_cards"]
    assert "rules/red-lines.md" in pack["required_checks"]
    assert any("高并发" in seed or "真实资金" in seed for seed in pack["hypothesis_seeds"])


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

    assert pack["selected_skill"] == "skills/web2-recon/SKILL.md"
    assert pack["knowledge_cards"] == [
        "knowledge/cards/api-idor.md",
        "knowledge/cards/coverage-prompts.md",
    ]


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
