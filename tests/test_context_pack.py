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
    assert any("H2.CL resource delivery" in seed and "victim JS import" in seed for seed in pack["hypothesis_seeds"])
    assert any("smuggling-to-WCD" in seed and "incomplete-header" in seed and "victim Cookie" in seed for seed in pack["hypothesis_seeds"])
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
    assert "rules/playbook-router.md" in pack["required_checks"]


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
    assert "rules/playbook-router.md" in pack["required_checks"]


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
    assert "rules/playbook-router.md" in pack["required_checks"]


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
    assert "rules/playbook-router.md" in pack["required_checks"]


def test_explicit_web_llm_focus_without_recon_routes_to_llm_card(tmp_path):
    pack = build_context_pack(tmp_path, target="target.com", focus="web-llm prompt-injection rag")

    assert pack["selected_skill"] == "skills/web2-vuln-classes/SKILL.md"
    assert pack["knowledge_cards"] == ["knowledge/cards/web-llm-tool-chains.md"]
    assert any("Web LLM" in seed or "工具" in seed for seed in pack["hypothesis_seeds"])


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
