"""Tests for tools/surface.py."""

import json

import finding_index
from memory.pattern_db import PatternDB
from memory.schemas import make_pattern_entry
from memory.target_profile import make_target_profile, save_target_profile
from runtime_state import update_runtime_state
from surface import format_surface_output, load_surface_context, rank_surface, unsafe_skipped_id
from tools.recon_adapter import ReconAdapter


class TestSurfaceContext:

    def test_loads_real_recon_layout_and_memory(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "\n".join([
                "https://api.target.com [200] [API] [Next.js,GraphQL,nginx] [1234]",
                "https://docs.target.com [403] [Documentation] [cloudflare] [456]",
            ]) + "\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/v2/users?id=123\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("/ws/notifications\n")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["next.js", "graphql"],
            tested_endpoints=["/api/v2/users/123"],
            untested_endpoints=["/graphql", "/api/v2/users?id=123"],
            hunt_sessions=2,
        ))
        PatternDB(memory_dir / "patterns.jsonl").save(make_pattern_entry(
            target="alpha.com",
            vuln_class="idor",
            technique="numeric_id_swap",
            tech_stack=["graphql"],
            payout=800,
        ))

        context = load_surface_context(repo_root, "target.com", memory_dir=memory_dir)
        assert context["available"] is True
        assert "https://api.target.com/graphql" in context["api_urls"]
        assert "/ws/notifications" in context["js_endpoints"]
        assert context["profile"]["hunt_sessions"] == 2

    def test_loads_runtime_state_and_recon_artifacts(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        update_runtime_state(repo_root, "target.com", mode="hunt", last_executed_workflow="run_vuln_scan")

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")

        assert context["runtime_state"]["last_executed_workflow"] == "run_vuln_scan"
        assert context["runtime_state"]["mode"] == "hunt"
        assert context["recon_artifacts"]["ready"] is True
        assert context["recon_artifacts"]["counts"]["hosts"] == 1


class TestSurfaceRanking:

    def test_ffuf_summary_enters_neutral_review_pool_without_off_target_promotion(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "dirs").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [Site] [nginx] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "dirs" / "ffuf_results.jsonl").write_text(
            "\n".join([
                json.dumps({
                    "url": "https://target.com/admin",
                    "status": 403,
                    "length": 123,
                    "words": 10,
                    "lines": 2,
                    "content-type": "text/html",
                    "input": {"FUZZ": "admin"},
                }),
                json.dumps({
                    "url": "https://external.example/api",
                    "status": 200,
                    "length": 456,
                    "words": 20,
                    "lines": 3,
                    "content-type": "application/json",
                    "input": {"FUZZ": "api"},
                }),
            ]) + "\n",
            encoding="utf-8",
        )
        ReconAdapter(recon_dir).summarize_ffuf_results()

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")

        assert context["ffuf_summary"]["available"] is True
        assert ranked["ffuf"]["observations"] == 2
        assert [item["url"] for item in ranked["review_pool"]] == ["https://target.com/admin"]
        item = ranked["review_pool"][0]
        assert item["ffuf_observed"] is True
        assert item["score"] == 0
        assert item["review_reason"] == "ffuf-observed route; AI triage required"
        assert "external.example" not in [entry["url"] for entry in ranked["review_pool"]]
        assert "FFUF Evidence (unranked; AI decides route value):" in output
        assert "Full evidence: recon/target.com/dirs/ffuf_results.jsonl" in output

    def test_ffuf_metadata_merges_into_stronger_existing_surface_once(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "dirs").mkdir(parents=True)
        url = "https://api.target.com/api/users?id=1"
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(url + "\n", encoding="utf-8")
        (recon_dir / "urls" / "with_params.txt").write_text(url + "\n", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "dirs" / "ffuf_results.jsonl").write_text(
            json.dumps({
                "url": url,
                "status": 200,
                "length": 456,
                "words": 20,
                "lines": 3,
                "content-type": "application/json",
                "input": {"FUZZ": "api/users?id=1"},
            }) + "\n",
            encoding="utf-8",
        )
        ReconAdapter(recon_dir).summarize_ffuf_results()

        ranked = rank_surface(
            load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        )
        matching = [item for item in ranked["review_pool"] if item["url"] == url]

        assert len(matching) == 1
        assert matching[0]["ffuf_observed"] is True
        assert matching[0]["score"] > 0
        assert matching[0]["review_reason"] != "ffuf-observed route; AI triage required"

    def test_ranks_graphql_and_untested_high(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "\n".join([
                "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]",
                "https://docs.target.com [403] [Documentation] [cloudflare] [500]",
            ]) + "\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/api/v2/users/123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/v2/report?id=123\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")

        memory_dir = tmp_path / "hunt-memory"
        (memory_dir / "targets").mkdir(parents=True)
        save_target_profile(memory_dir, make_target_profile(
            "target.com",
            tech_stack=["graphql", "next.js"],
            tested_endpoints=["/api/v2/users/123"],
            untested_endpoints=["/graphql", "/api/v2/report?id=123"],
            hunt_sessions=1,
        ))
        PatternDB(memory_dir / "patterns.jsonl").save(make_pattern_entry(
            target="beta.com",
            vuln_class="idor",
            technique="id_swap",
            tech_stack=["graphql"],
            payout=500,
        ))

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=memory_dir))
        assert ranked["available"] is True
        assert ranked["p1"]
        assert "graphql" in ranked["p1"][0]["url"]
        assert any(part["source"] == "attack_value" for part in ranked["p1"][0]["score_breakdown"])
        kill_hosts = [item["host"] for item in [__import__("json").loads(x) for x in ranked["kill"]]]
        assert "docs.target.com" in kill_hosts

    def test_cf_bypass_403_hosts_become_refresh_leads_not_kill(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "cf_cookies.txt").write_text("cf_clearance=old\n", encoding="utf-8")

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [403] [Just a moment...] [cloudflare] [500]\n",
            encoding="utf-8",
        )

        ranked = rank_surface(
            load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        )

        kill_hosts = [json.loads(item)["host"] for item in ranked["kill"]]
        assert "app.target.com" not in kill_hosts

        workflow_leads = [json.loads(item) for item in ranked["workflow_leads"]]
        cf_leads = [item for item in workflow_leads if item.get("category") == "cf-bypass-refresh"]
        assert cf_leads
        assert cf_leads[0]["source"] == "cf_solver"
        assert "--check --auto-resolve" in cf_leads[0]["next_action"]
        assert cf_leads[0]["artifact"] == "recon/target.com/cf_cookies.txt"

    def test_surface_does_not_rank_off_target_scanner_findings_as_direct_surface(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        findings_dir = repo_root / "findings" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        findings_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (findings_dir / "findings.json").write_text(
            json.dumps({
                "findings": [
                    {
                        "id": "OFFTARGET-IDOR",
                        "type": "idor",
                        "severity": "high",
                        "confidence": "confirmed",
                        "url": "https://steamcommunity.com/sharedfiles/filedetails/?id=1969196030",
                    },
                    {
                        "id": "TARGET-AUTHZ",
                        "type": "auth_bypass",
                        "severity": "high",
                        "confidence": "high",
                        "url": "https://api.target.com/rest/admin/application-configuration",
                    },
                ]
            }),
            encoding="utf-8",
        )

        ranked = rank_surface(
            load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        )

        ranked_urls = [item["url"] for item in ranked["p1"] + ranked["p2"]]
        assert "https://api.target.com/rest/admin/application-configuration" in ranked_urls
        assert all("steamcommunity.com" not in url for url in ranked_urls)

    def test_external_urls_become_chain_context_lead_not_direct_surface(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/rest/admin/application-configuration\n"
            "https://ethereum.example.net/v1/mainnet/jsonrpc\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://github.com/org/repo/issues?id=1\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")

        ranked = rank_surface(
            load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        )

        ranked_urls = [item["url"] for item in ranked["p1"] + ranked["p2"]]
        assert "https://api.target.com/rest/admin/application-configuration" in ranked_urls
        assert all("ethereum.example.net" not in url for url in ranked_urls)
        assert all("github.com" not in url for url in ranked_urls)

        workflow_leads = [json.loads(item) for item in ranked["workflow_leads"]]
        external_leads = [
            item for item in workflow_leads
            if item.get("category") == "external-chain-context"
        ]
        assert external_leads
        assert "ethereum.example.net" in external_leads[0]["evidence"]
        assert "do not run direct vulnerability validation" in external_leads[0]["next_action"]

    def test_surface_output_shows_runtime_and_recon_cache(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Next.js,GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        update_runtime_state(repo_root, "target.com", mode="hunt", last_executed_workflow="run_vuln_scan")

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        output = format_surface_output(ranked, "target.com")

        assert "Last Workflow:" in output
        assert "- run_vuln_scan (mode: hunt)" in output
        assert "Recon Cache:" in output
        assert "- Hosts: 1, surface inputs: 1, structured findings: 0" in output
        assert "AI Review Pool (advisory; Claude chooses final priority):" in output
        assert ranked["review_pool"][0]["url"] == "https://api.target.com/graphql"
        assert ranked["review_pool"][0]["review_reason"]

    def test_target_memory_feeds_surface_output_and_workflow_leads(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        goals_dir = repo_root / "memory" / "goals"
        target_dir = goals_dir / "targets"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        target_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/api/org/123/users\n"
            "https://api.target.com/api/health\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (goals_dir / "active.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "active_goal": "test org API authorization",
                    "current_hypothesis": "org_id may be user-controlled",
                }
            ),
            encoding="utf-8",
        )
        (target_dir / "target.com.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "active_leads": [{"text": "/api/org/{id}/users"}],
                    "next_actions": [{"text": "continue /api/org/{id}/users role diff"}],
                    "dead_ends": [{"text": "GraphQL introspection alone is not reportable"}],
                    "session_handoffs": [
                        {
                            "path": "memory/goals/sessions/example.md",
                            "summary": "continue org API role diff",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")
        workflow_leads = [
            json.loads(item) if isinstance(item, str) else item
            for item in ranked["workflow_leads"]
        ]

        assert context["target_goal_memory"]["active_matches"] is True
        assert ranked["p1"][0]["url"] == "https://api.target.com/api/org/123/users"
        assert any(
            part["source"] == "target_memory" and part["score"] > 0
            for part in ranked["p1"][0]["score_breakdown"]
        )
        assert ranked["target_memory"]["goal"] == "test org API authorization"
        assert workflow_leads[0]["source"] == "target_memory"
        assert workflow_leads[0]["category"] == "active-lead"
        assert "Source: target memory" in output
        assert "Target Memory:" in output
        assert "Goal: test org API authorization" in output
        assert "Hypothesis: org_id may be user-controlled" in output
        assert "/api/org/{id}/users" in output
        assert "continue org API role diff" in output
        assert "[high] active-lead: /api/org/{id}/users" in output

    def test_target_memory_dead_end_deprioritizes_matching_surface(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        target_dir = repo_root / "memory" / "goals" / "targets"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        target_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/api/org/123/users\n"
            "https://api.target.com/api/org/123/settings\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (target_dir / "target.com.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "dead_ends": [{"text": "/api/org/{id}/users already tested with owned accounts"}],
                }
            ),
            encoding="utf-8",
        )
        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        output = format_surface_output(ranked, "target.com")
        users_entry = next(
            item for item in ranked["p1"] + ranked["p2"]
            if item["url"] == "https://api.target.com/api/org/123/users"
        )

        assert ranked["p1"][0]["url"] == "https://api.target.com/api/org/123/settings"
        assert any(
            part["source"] == "target_memory" and part["score"] == -4
            for part in users_entry["score_breakdown"]
        )
        assert users_entry["target_memory_dead_ends"][0]["text"].startswith("/api/org/{id}/users")
        assert "Caution: matches remembered dead end" in output
        assert "avoid repeating remembered dead end" in users_entry["suggested"]

    def test_exposure_signals_become_soft_workflow_leads_only(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "exposure" / "api_leaks").mkdir(parents=True)
        (recon_dir / "exposure" / "identity_intel").mkdir(parents=True)
        (recon_dir / "exposure" / "cloud").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI,GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "exposure" / "api_doc_candidates.txt").write_text(
            "[urls] https://api.target.com/openapi.json\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leak_candidates.txt").write_text(
            "https://www.postman.com/target/workspace/collection\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leak_trufflehog_verified.jsonl").write_text(
            '{"Verified":true}\n',
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leaks" / "swagger_leaks.txt").write_text(
            "https://api.target.com/swagger.json\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "api_leaks" / "postman_leaks.txt").write_text(
            "postman collection: target\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "config_files.txt").write_text(
            "[EXPOSED] https://api.target.com/env.js\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "cloud_storage_candidates.txt").write_text(
            "https://target.s3.amazonaws.com/private/\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "identity_intel" / "emails.txt").write_text(
            "admin@target.com\nops@target.com\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "identity_intel" / "leaksearch.txt").write_text(
            "target leak hit\n",
            encoding="utf-8",
        )
        (recon_dir / "exposure" / "cloud" / "cloud_enum.txt").write_text(
            "target-backup\n",
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        output = format_surface_output(ranked, "target.com")
        workflow_leads = [
            json.loads(item) if isinstance(item, str) else item
            for item in ranked["workflow_leads"]
        ]
        categories = [item["category"] for item in workflow_leads]

        assert categories[:5] == [
            "verified-secret",
            "api-leak",
            "api-docs",
            "config-cloud",
            "identity-cloud",
        ]
        assert all(item["source"] == "recon_exposure" for item in workflow_leads[:5])
        assert "[critical] verified-secret: Verified secret material found in API leak artifacts" in output
        assert "Next: inspect recon/target.com/exposure/api_leak_trufflehog_verified.jsonl" in output
        assert "[high] api-leak: API leak candidates from Postman/OpenAPI discovery" in output
        assert "[high] api-docs: OpenAPI/Swagger/API documentation candidates discovered" in output
        assert "[medium] config-cloud: Config/cloud exposure candidates discovered" in output
        assert "[medium] identity-cloud: Identity/cloud intel signals discovered" in output
        for item in ranked["p1"] + ranked["p2"]:
            assert all(part["source"] != "recon_exposure" for part in item.get("score_breakdown", []))

    def test_openapi_semantics_becomes_one_soft_workflow_lead(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "exposure").mkdir(parents=True)
        (recon_dir / "api_specs").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/users\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "exposure" / "api_doc_candidates.txt").write_text(
            "https://api.target.com/openapi.json\n",
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "spec_urls.txt").write_text(
            "https://api.target.com/openapi.json\n",
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "operations.jsonl").write_text(
            '{"method":"GET","url":"https://api.target.com/users"}\n',
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "public_operations.txt").write_text(
            "GET\thttps://api.target.com/health\texplicit_public\n",
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "auth_boundary_candidates.jsonl").write_text(
            '{"method":"GET","url":"https://api.target.com/users"}\n',
            encoding="utf-8",
        )
        (recon_dir / "api_specs" / "platform_metadata.jsonl").write_text(
            '{"kind":"oauth_authorization_server"}\n',
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        output = format_surface_output(ranked, "target.com")
        workflow_leads = [
            json.loads(item) if isinstance(item, str) else item
            for item in ranked["workflow_leads"]
        ]
        semantic_leads = [item for item in workflow_leads if item["category"] == "openapi-semantics"]

        assert len(semantic_leads) == 1
        assert semantic_leads[0]["priority"] == "high"
        assert "anonymous baseline plus controlled authentication" in semantic_leads[0]["next_action"]
        assert not any(item["category"] == "api-docs" for item in workflow_leads)
        assert "[high] openapi-semantics" in output
        for item in ranked["p1"] + ranked["p2"]:
            assert all(part["source"] != "recon_exposure" for part in item.get("score_breakdown", []))

    def test_platform_metadata_only_lead_points_to_nonempty_artifact(self, tmp_path):
        recon_dir = tmp_path / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "api_specs").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [App] [nginx] [100]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "api_specs" / "platform_metadata.jsonl").write_text(
            '{"kind":"oauth_authorization_server"}\n',
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(tmp_path, "target.com", memory_dir=tmp_path / "hunt-memory"))
        lead = next(
            json.loads(item) if isinstance(item, str) else item
            for item in ranked["workflow_leads"]
            if (json.loads(item) if isinstance(item, str) else item)["category"] == "openapi-semantics"
        )

        assert lead["priority"] == "medium"
        assert lead["artifact"] == "recon/target.com/api_specs/platform_metadata.jsonl"
        assert "advertised authorization servers" in lead["next_action"]

    def test_unsafe_skipped_artifact_becomes_workflow_lead(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        findings_dir = repo_root / "findings" / "target.com" / "manual_review"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        findings_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/profile\n",
            encoding="utf-8",
        )
        (findings_dir / "unsafe_skipped.txt").write_text(
            "2026-06-07T00:00:00Z\tmethod=PUT\tlabel=HTTP method tampering probes\turl=https://api.target.com/profile\treason=requires opt-in\n",
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        output = format_surface_output(ranked, "target.com")
        workflow_leads = [
            json.loads(item) if isinstance(item, str) else item
            for item in ranked["workflow_leads"]
        ]

        assert workflow_leads[0]["source"] == "scanner_manual_review"
        assert workflow_leads[0]["category"] == "action-gated"
        assert "[high] action-gated: Side-effect-capable scanner probes were skipped" in output
        assert "findings/target.com/manual_review/unsafe_skipped.txt" in output
        assert "ALLOW_UNSAFE_HTTP_TESTS=1" in output

    def test_resolved_unsafe_skipped_artifact_is_hidden_from_workflow_leads(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        findings_dir = repo_root / "findings" / "target.com" / "manual_review"
        state_dir = repo_root / "state" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        findings_dir.mkdir(parents=True)
        state_dir.mkdir(parents=True)

        line = "2026-06-07T00:00:00Z\tmethod=PUT\tlabel=HTTP method tampering probes\turl=https://api.target.com/profile\treason=requires opt-in"
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/profile\n",
            encoding="utf-8",
        )
        (findings_dir / "unsafe_skipped.txt").write_text(line + "\n", encoding="utf-8")
        (state_dir / "unsafe_skipped_reviews.json").write_text(
            json.dumps({"resolved": {unsafe_skipped_id(line): {"status": "blocked"}}}),
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        workflow_leads = [
            json.loads(item) if isinstance(item, str) else item
            for item in ranked["workflow_leads"]
        ]

        assert not any(item.get("category") in {"unsafe-skipped", "action-gated"} for item in workflow_leads)

    def test_demoted_manual_review_artifacts_become_soft_workflow_leads(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        findings_dir = repo_root / "findings" / "target.com" / "manual_review"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        findings_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/profile\n",
            encoding="utf-8",
        )
        (findings_dir / "open_200_api.txt").write_text(
            "[OPEN-200-REVIEW] 200 1200 https://api.target.com/profile\n",
            encoding="utf-8",
        )
        (findings_dir / "standard_public_metadata.txt").write_text(
            "[STANDARD-PUBLIC-METADATA] 200 https://api.target.com/.well-known/openid-configuration\n",
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        output = format_surface_output(ranked, "target.com")
        workflow_leads = [
            json.loads(item) if isinstance(item, str) else item
            for item in ranked["workflow_leads"]
        ]

        categories = [item["category"] for item in workflow_leads]
        assert "open-200-api-review" in categories
        assert "public-metadata" in categories
        assert "findings/target.com/manual_review/open_200_api.txt" in output
        assert "findings/target.com/manual_review/standard_public_metadata.txt" in output

    def test_reranks_structured_scanner_findings_into_p1(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        findings_dir = repo_root / "findings" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        findings_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/health\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/search?q=test\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "total": 1,
                    "findings": [
                        {
                            "id": "sqli_deadbeef",
                            "type": "sqli",
                            "category": "sqli",
                            "url": "https://api.target.com/search?q=test",
                            "severity": "high",
                            "confidence": "confirmed",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                            "source_file": "sqli/timebased_candidates.txt",
                            "summary": "[SQLI-POC-VERIFIED] https://api.target.com/search?q=test",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")

        assert context["scanner_findings"][0]["id"] == "sqli_deadbeef"
        assert ranked["p1"][0]["url"] == "https://api.target.com/search?q=test"
        assert any(reason.startswith("scanner finding: sqli status=not_generated") for reason in ranked["p1"][0]["reasons"])
        assert any(
            part["source"] == "scanner" and part["score"] == 15
            for part in ranked["p1"][0]["score_breakdown"]
        )
        assert ranked["p1"][0]["score"] == sum(
            part["score"] for part in ranked["p1"][0]["score_breakdown"]
        )
        assert "validate sqli evidence" in ranked["p1"][0]["suggested"]
        assert ranked["scanner"]["finding_count"] == 1
        assert "Score:" in output
        assert "scanner +15" in output
        assert "Structured scanner candidates: 1" in output
        assert "sqli_deadbeef [high/confirmed] sqli status=unvalidated/not_generated" in output

    def test_browser_observed_api_endpoint_is_visible_and_boosted(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "browser").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [App] [React] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "browser" / "xhr_endpoints.txt").write_text(
            "https://app.target.com/api/admin/export?order_id=42\n",
            encoding="utf-8",
        )
        (recon_dir / "browser" / "api_endpoints.txt").write_text(
            "https://app.target.com/api/admin/export?order_id=42\n",
            encoding="utf-8",
        )

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")

        assert context["browser_xhr_urls"] == ["https://app.target.com/api/admin/export?order_id=42"]
        assert ranked["p1"][0]["browser_observed"] is True
        assert any(part["source"] == "browser" for part in ranked["p1"][0]["score_breakdown"])
        assert "Source: browser-observed XHR/API" in output
        assert "Browser-observed XHR/API: 1 xhr, 1 api" in output

    def test_review_pool_keeps_score_only_tail_out_when_evidence_rich_exists(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "browser").mkdir(parents=True)

        browser_url = "https://app.target.com/rest/languages"
        score_only_url = "https://app.target.com/rest/deluxe-membership"
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [App] [React] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            score_only_url + "\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "browser" / "xhr_endpoints.txt").write_text(
            browser_url + "\n",
            encoding="utf-8",
        )
        (recon_dir / "browser" / "api_endpoints.txt").write_text(
            browser_url + "\n",
            encoding="utf-8",
        )

        ranked = rank_surface(
            load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        )

        assert ranked["review_pool"][0]["url"] == browser_url
        assert ranked["review_pool"][0]["review_reason"] == "browser-observed API/workflow"
        assert any(item["url"] == score_only_url for item in ranked["p1"] + ranked["p2"])
        assert all(item["url"] != score_only_url for item in ranked["review_pool"])

    def test_review_pool_falls_back_to_score_only_when_no_actionable_evidence_exists(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "browser").mkdir(parents=True)

        score_only_url = "https://app.target.com/rest/deluxe-membership"
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [App] [React] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            score_only_url + "\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "browser" / "xhr_endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "browser" / "api_endpoints.txt").write_text("", encoding="utf-8")

        ranked = rank_surface(
            load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        )

        assert ranked["review_pool"][0]["url"] == score_only_url
        assert ranked["review_pool"][0]["review_reason"] == "top advisory score (low-evidence fallback)"

    def test_js_reader_hypotheses_feed_surface_ranking(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        js_intel_dir = repo_root / "findings" / "target.com" / "js_intel"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        js_intel_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [App] [React] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (js_intel_dir / "hypotheses.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "endpoints": [
                        {
                            "method": "POST",
                            "path": "/api/admin/export?order_id=42",
                            "source_file": "recon/target.com/js_dump/admin.js",
                            "evidence": "fetch('/api/admin/export?order_id=' + id)",
                            "auth_required": "true",
                        }
                    ],
                    "graphql_operations": [
                        {"name": "ExportOrders", "type": "mutation", "file": "admin.js"}
                    ],
                    "attack_surface_leads": [
                        {
                            "title": "Admin export IDOR",
                            "category": "IDOR",
                            "next_action": "swap order_id under a lower-privileged session",
                            "priority": "high",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")

        assert context["js_intel"]["endpoints"][0]["path"] == "/api/admin/export?order_id=42"
        assert ranked["p1"][0]["url"] == "https://app.target.com/api/admin/export?order_id=42"
        assert ranked["p1"][0]["js_intel_observed"] is True
        assert any(part["source"] == "js_intel" for part in ranked["p1"][0]["score_breakdown"])
        assert ranked["js_intel"] == {"endpoint_count": 1, "lead_count": 1, "graphql_count": 1}
        assert "Source: js-reader hypotheses" in output
        assert "JS-reader hypotheses: 1 endpoints, 1 leads, 1 GraphQL operations" in output
        assert "Workflow Leads:" in output
        assert "[high] idor: Admin export IDOR" in output
        assert "Next: swap order_id under a lower-privileged session" in output

    def test_source_intel_hypotheses_feed_surface_ranking(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        source_intel_dir = repo_root / "findings" / "target.com" / "source_intel"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        source_intel_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [App] [React,GraphQL] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://app.target.com/graphql\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (source_intel_dir / "routes.json").write_text(
            json.dumps(
                {
                    "routes": [
                        {"route": "/graphql", "method": "POST", "source": "repo:app.js"},
                        {"route": "/api/users/:id/orders", "method": "GET", "source": "repo:orders.js"},
                    ],
                    "graphql_operations": [
                        {"operation": "mutation", "name": "ApproveOrder", "source": "repo:app.js"}
                    ],
                }
            ),
            encoding="utf-8",
        )
        (source_intel_dir / "hypotheses.jsonl").write_text(
            "\n".join([
                json.dumps(
                    {
                        "type": "idor",
                        "candidate": "/api/users/:id/orders",
                        "reason": "route contains object/account/user id marker",
                        "source": "repo:orders.js",
                    }
                ),
                json.dumps(
                    {
                        "type": "business-logic",
                        "candidate": "ApproveOrder",
                        "reason": "GraphQL mutation can hide workflow authz checks",
                        "source": "repo:app.js",
                    }
                ),
            ]) + "\n",
            encoding="utf-8",
        )

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")

        graphql_entry = next(item for item in ranked["p1"] if item["url"] == "https://app.target.com/graphql")
        assert context["source_intel"]["hypotheses"][0]["type"] == "idor"
        assert graphql_entry["source_intel_observed"] is True
        assert any(part["source"] == "intel" and "Source-intel hypothesis" in part["label"] for part in graphql_entry["score_breakdown"])
        assert ranked["source_intel"] == {"hypothesis_count": 2, "route_count": 2, "graphql_count": 1}
        assert "Source: source-intel hypotheses" in output
        assert "Source-intel hypotheses: 2, routes: 2, GraphQL operations: 1" in output
        assert "[high] idor: /api/users/:id/orders" in output
        assert "Next: route contains object/account/user id marker" in output

    def test_browser_js_source_convergence_feeds_surface_and_workflow_leads(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        js_intel_dir = repo_root / "findings" / "target.com" / "js_intel"
        source_intel_dir = repo_root / "findings" / "target.com" / "source_intel"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "browser").mkdir(parents=True)
        js_intel_dir.mkdir(parents=True)
        source_intel_dir.mkdir(parents=True)

        converged_url = "https://app.target.com/api/admin/export?order_id=42"
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [App] [React] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "urls" / "with_params.txt").write_text("", encoding="utf-8")
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (recon_dir / "browser" / "xhr_endpoints.txt").write_text(converged_url + "\n", encoding="utf-8")
        (recon_dir / "browser" / "api_endpoints.txt").write_text(converged_url + "\n", encoding="utf-8")
        (js_intel_dir / "hypotheses.json").write_text(
            json.dumps({
                "endpoints": [
                    {
                        "method": "POST",
                        "path": "/api/admin/export?order_id=42",
                        "source_file": "admin.js",
                        "auth_required": "true",
                    }
                ],
                "attack_surface_leads": [],
                "graphql_operations": [],
            }),
            encoding="utf-8",
        )
        (source_intel_dir / "routes.json").write_text(
            json.dumps({"routes": [{"route": "/api/admin/export?order_id=42", "method": "POST"}]}),
            encoding="utf-8",
        )
        (source_intel_dir / "hypotheses.jsonl").write_text(
            json.dumps({
                "type": "idor",
                "candidate": "/api/admin/export?order_id=42",
                "reason": "admin export route uses order_id",
                "source": "routes/export.py",
            }) + "\n",
            encoding="utf-8",
        )
        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        output = format_surface_output(ranked, "target.com")
        workflow_leads = [
            json.loads(item) if isinstance(item, str) else item
            for item in ranked["workflow_leads"]
        ]

        assert ranked["p1"][0]["url"] == converged_url
        assert ranked["p1"][0]["evidence_convergence"] == ["browser", "js", "source"]
        assert any(part["source"] == "evidence_convergence" for part in ranked["p1"][0]["score_breakdown"])
        assert workflow_leads[0]["source"] == "evidence_convergence"
        assert workflow_leads[0]["priority"] == "critical"
        assert "Source: cross-evidence convergence (browser+js+source)" in output
        assert "[critical] browser+js+source" in output

    def test_deprioritizes_reported_scanner_findings(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        findings_dir = repo_root / "findings" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        findings_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text("")
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/reported?q=1\nhttps://api.target.com/fresh?q=1\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "total": 2,
                    "findings": [
                        {
                            "id": "sqli_reported",
                            "type": "sqli",
                            "url": "https://api.target.com/reported?q=1",
                            "severity": "high",
                            "confidence": "confirmed",
                            "validation_status": "validated",
                            "report_status": "generated",
                        },
                        {
                            "id": "mfa_fresh",
                            "type": "mfa",
                            "url": "https://api.target.com/fresh?q=1",
                            "severity": "medium",
                            "confidence": "high",
                            "validation_status": "unvalidated",
                            "report_status": "not_generated",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        finding_index.update_finding_status(
            findings_dir,
            "sqli_reported",
            validation_status="validated",
            report_status="generated",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        output = format_surface_output(ranked, "target.com")

        assert ranked["p1"][0]["url"] == "https://api.target.com/fresh?q=1"
        assert "mfa_fresh [medium/high] mfa status=unvalidated/not_generated" in output
        assert "sqli_reported [high/confirmed] sqli status=validated/generated" not in output
        reported_items = [
            item for item in ranked["p1"] + ranked["p2"]
            if item["url"] == "https://api.target.com/reported?q=1"
        ]
        if reported_items:
            assert reported_items[0]["score"] < ranked["p1"][0]["score"]
            assert "already reported/generated" in reported_items[0]["suggested"]

    def test_reported_high_value_scanner_finding_does_not_dominate_p1(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        findings_dir = repo_root / "findings" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        findings_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/rest/admin/application-configuration\n"
            "https://api.target.com/api/fresh?q=1\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/fresh?q=1\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")
        (findings_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "total": 1,
                    "findings": [
                        {
                            "id": "authz_reported",
                            "type": "auth_bypass",
                            "url": "https://api.target.com/rest/admin/application-configuration",
                            "severity": "high",
                            "confidence": "confirmed",
                            "validation_status": "validated",
                            "report_status": "generated",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        finding_index.update_finding_status(
            findings_dir,
            "authz_reported",
            validation_status="validated",
            report_status="generated",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        ranked_urls = [item["url"] for item in ranked["p1"]]

        assert "https://api.target.com/api/fresh?q=1" in ranked_urls
        assert "https://api.target.com/rest/admin/application-configuration" not in ranked_urls

    def test_ledger_tested_clean_authz_is_lane_history_not_surface_exclusion(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        ledger_dir = repo_root / "memory" / "evidence" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        ledger_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/rest/admin/application-version\n"
            "https://api.target.com/api/fresh?q=1\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/fresh?q=1\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")
        (ledger_dir / "ledger.jsonl").write_text(
            json.dumps({
                "endpoint": "/rest/admin/application-version",
                "vuln_class": "Authz",
                "result": "tested_clean",
            }) + "\n",
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        ranked_urls = [item["url"] for item in ranked["p1"]]
        review_urls = [item["url"] for item in ranked["review_pool"]]

        assert "https://api.target.com/api/fresh?q=1" in ranked_urls
        assert "https://api.target.com/rest/admin/application-version" in ranked_urls
        assert "https://api.target.com/rest/admin/application-version" in review_urls
        item = next(
            item for item in ranked["p1"]
            if item["url"] == "https://api.target.com/rest/admin/application-version"
        )
        assert item["ledger_history"] == {
            "endpoint": "/rest/admin/application-version",
            "vuln_class": "Authz",
            "result": "tested_clean",
        }

    def test_action_queue_final_status_is_history_not_surface_exclusion(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        queue_dir = repo_root / "state" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        queue_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [SPA] [React] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://app.target.com/orders\n"
            "https://app.target.com/rest/order-history\n"
            "https://app.target.com/rest/track-order/abc123\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text("")
        (recon_dir / "js" / "endpoints.txt").write_text("")
        (queue_dir / "action_queue.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": "target.com",
                    "actions": [
                        {
                            "status": "n/a",
                            "type": "ranked-surface",
                            "metadata": {
                                "url": "https://app.target.com/orders",
                                "endpoint": "/orders",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        p1_urls = [item["url"] for item in ranked["p1"]]
        visible_urls = [item["url"] for item in ranked["p1"] + ranked["p2"]]
        review_urls = [item["url"] for item in ranked["review_pool"]]

        assert "https://app.target.com/orders" in p1_urls
        assert "https://app.target.com/orders" in visible_urls
        assert "https://app.target.com/orders" in review_urls
        orders = next(item for item in ranked["p1"] if item["url"] == "https://app.target.com/orders")
        assert orders["action_queue_history"]["status"] == "n/a"
        assert "https://app.target.com/rest/order-history" in p1_urls

    def test_surface_uses_resolver_normalization_and_blocked_redline(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        ledger_dir = repo_root / "memory" / "evidence" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        ledger_dir.mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [FastAPI] [1000]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/api/sqli/search?q=test\n"
            "https://api.target.com/api/import?url=https://example.test\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/api/sqli/search?q=test\n"
            "https://api.target.com/api/import?url=https://example.test\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (ledger_dir / "ledger.jsonl").write_text(
            json.dumps({
                "endpoint": "/api/sqli/search/",
                "vuln_class": "sqli",
                "result": "tested_clean",
            }) + "\n" + json.dumps({
                "endpoint": "/api/import",
                "vuln_class": "ssrf",
                "result": "blocked_redline",
            }) + "\n",
            encoding="utf-8",
        )

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        items = {item["url"]: item for item in ranked["p1"] + ranked["p2"]}

        sqli = items["https://api.target.com/api/sqli/search?q=test"]
        ssrf = items["https://api.target.com/api/import?url=https://example.test"]
        assert sqli["ledger_history"]["result"] == "tested_clean"
        assert sqli["ledger_history"]["vuln_class"] == "SQLi"
        assert ssrf["ledger_history"]["result"] == "blocked_redline"
        assert ssrf["ledger_history"]["vuln_class"] == "SSRF"
        assert sqli["url"] in [item["url"] for item in ranked["review_pool"]]
        assert ssrf["url"] in [item["url"] for item in ranked["review_pool"]]

    def test_bare_numeric_paths_do_not_become_p1_sequential_objects(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [SPA] [React] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://app.target.com/16\n"
            "https://app.target.com/orders/16\n"
            "https://app.target.com/search?q=test\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://app.target.com/search?q=test\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")

        ranked = rank_surface(load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory"))
        p1_urls = [item["url"] for item in ranked["p1"]]

        assert "https://app.target.com/orders/16" in p1_urls
        assert "https://app.target.com/16" not in p1_urls
        assert not any(
            item["url"] == "https://app.target.com/16"
            and item["reasons"][0] == "Sequential object reference"
            for item in ranked["p1"] + ranked["p2"]
        )

    def test_reranks_local_intel_signals(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)

        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [API] [Express] [1000]\n"
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/oauth/callback\n"
        )
        (recon_dir / "urls" / "with_params.txt").write_text(
            "https://api.target.com/oauth/callback?redirect_uri=https://client.example/cb&state=abc\n"
        )
        (recon_dir / "js" / "endpoints.txt").write_text("")
        (recon_dir / "intel.json").write_text(
            json.dumps(
                {
                    "target": "target.com",
                    "critical": [],
                    "high": [
                        {
                            "id": "https://hackerone.com/reports/1",
                            "source": "HackerOne",
                            "tech": "oauth",
                            "severity": "HIGH",
                            "summary": "OAuth redirect_uri bypass leads to account takeover",
                        }
                    ],
                    "info": [],
                }
            ),
            encoding="utf-8",
        )

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")

        assert context["intel_signals"][0]["class"] == "oauth"
        assert ranked["p1"][0]["url"] == "https://api.target.com/oauth/callback?redirect_uri=https://client.example/cb&state=abc"
        assert any(reason.startswith("intel signal: oauth") for reason in ranked["p1"][0]["reasons"])
        assert any(
            part["source"] == "intel" and part["score"] == 9
            for part in ranked["p1"][0]["score_breakdown"]
        )
        # Structural invariant: total equals sum of breakdown contributions
        # (holds regardless of value-class weighting being on or off).
        assert ranked["p1"][0]["score"] == sum(
            part["score"] for part in ranked["p1"][0]["score_breakdown"]
        )
        assert ranked["intel"]["signal_count"] == 1
        # Output preserves attack + intel contributions (do not pin total —
        # value-class weighting amplifies high-value paths like /oauth/callback).
        assert "intel +9" in output
        assert "Local intel signals: 1" in output
        assert "oauth [HIGH]" in output

    def test_v2_intel_projection_preserves_coverage_and_degraded_sources(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://api.target.com [200] [1000] [API] [Express]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://api.target.com/oauth/callback?redirect_uri=https://client.test/cb\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        advisory = {
            "id": "CVE-2026-1000",
            "aliases": ["CVE-2026-1000"],
            "source": "github_advisory",
            "source_names": ["github_advisory", "nvd"],
            "component": {
                "name": "express",
                "version": "5.1.0",
                "hosts": ["api.target.com"],
                "ports": [443],
                "protocols": ["tcp"],
                "cpes": ["cpe:2.3:a:example:express:5.1.0:*:*:*:*:*:*:*"],
            },
            "applicability": "affected",
            "severity": "HIGH",
            "summary": "OAuth redirect_uri validation bypass",
            "score_hint": 92,
            "kev": True,
            "epss": 0.88,
            "already_tested": True,
            "source_refs": [],
        }
        (recon_dir / "intel.json").write_text(json.dumps({
            "schema_version": 2,
            "target": "target.com",
            "generated_at": "2026-07-19T00:00:00Z",
            "coverage_status": "partial",
            "inventory": {"status": "ready", "components": [], "hosts": [], "stats": {}},
            "sources": [
                {"source": "github_advisory", "status": "ok", "fetched_at": "2026-07-19T00:00:00Z"},
                {"source": "nvd", "status": "error", "fetched_at": "2026-07-19T00:00:00Z", "error": "rate limited"},
            ],
            "advisories": [advisory],
            "critical": [advisory],
            "high": [],
            "info": [],
        }), encoding="utf-8")

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")

        assert context["intel"]["status"] == "ready"
        assert context["intel"]["coverage_status"] == "partial"
        assert context["intel"]["degraded_sources"] == [{
            "source": "nvd",
            "status": "error",
            "error": "rate limited",
            "stale": False,
        }]
        assert context["intel_signals"][0]["kev"] is True
        assert context["intel"]["review_items"][0]["id"] == "CVE-2026-1000"
        assert context["intel"]["review_items"][0]["component"]["ports"] == [443]
        assert context["intel"]["review_items"][0]["component"]["protocols"] == ["tcp"]
        assert context["intel"]["review_items"][0]["already_tested"] is True
        assert ranked["intel"]["signal_count"] == 1
        assert "Artifact status: ready; coverage: partial" in output
        assert "Degraded source: nvd [error]" in output
        assert "Advisory review: CVE-2026-1000 [HIGH/affected] score=92" in output

    def test_generic_high_score_advisory_remains_visible_without_class_keyword(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://app.target.com [200] [1000] [App] [Next.js:15.2.1]\n",
            encoding="utf-8",
        )
        (recon_dir / "urls" / "api_endpoints.txt").write_text(
            "https://app.target.com/health\n",
            encoding="utf-8",
        )
        (recon_dir / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        advisory = {
            "id": "CVE-2026-2000",
            "aliases": ["CVE-2026-2000"],
            "source_names": ["osv", "nvd"],
            "component": {"name": "next.js", "version": "15.2.1"},
            "applicability": "affected",
            "severity": "CRITICAL",
            "summary": "Remote code execution in image optimizer",
            "score_hint": 140,
            "score_reasons": ["applicability=affected", "CISA KEV"],
            "kev": True,
            "epss": 0.95,
            "source_refs": [],
        }
        (recon_dir / "intel.json").write_text(json.dumps({
            "schema_version": 2,
            "target": "target.com",
            "generated_at": "2026-07-19T00:00:00Z",
            "coverage_status": "ready",
            "inventory": {"status": "ready", "components": [], "hosts": [], "stats": {}},
            "sources": [{
                "source": "osv",
                "status": "ok",
                "fetched_at": "2026-07-19T00:00:00Z",
            }],
            "advisories": [advisory],
            "critical": [advisory],
            "high": [],
            "info": [],
        }), encoding="utf-8")

        context = load_surface_context(
            repo_root,
            "target.com",
            memory_dir=repo_root / "hunt-memory",
        )
        output = format_surface_output(rank_surface(context), "target.com")

        assert context["intel_signals"] == []
        assert context["intel"]["review_item_count"] == 1
        assert "Advisory review: CVE-2026-2000 [CRITICAL/affected] score=140" in output

    def test_invalid_intel_artifact_is_not_projected_as_clean(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "urls").mkdir(parents=True)
        (recon_dir / "js").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [1000] [Target] [nginx]\n",
            encoding="utf-8",
        )
        (recon_dir / "intel.json").write_text("{broken", encoding="utf-8")

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")
        ranked = rank_surface(context)
        output = format_surface_output(ranked, "target.com")

        assert context["intel"]["status"] == "invalid"
        assert context["intel"]["coverage_status"] == "error"
        assert ranked["intel"]["signal_count"] == 0
        assert "Artifact status: invalid; coverage: error" in output
        assert "Intel artifact error:" in output

    def test_unknown_intel_schema_is_invalid_not_empty_legacy(self, tmp_path):
        repo_root = tmp_path
        recon_dir = repo_root / "recon" / "target.com"
        (recon_dir / "live").mkdir(parents=True)
        (recon_dir / "live" / "httpx_full.txt").write_text(
            "https://target.com [200] [1000] [Target] [nginx]\n",
            encoding="utf-8",
        )
        (recon_dir / "intel.json").write_text(
            json.dumps({"schema_version": 999, "critical": [], "high": [], "info": []}),
            encoding="utf-8",
        )

        context = load_surface_context(repo_root, "target.com", memory_dir=repo_root / "hunt-memory")

        assert context["intel"]["status"] == "invalid"
        assert "unsupported intel artifact schema" in context["intel"]["error"]

    def test_format_missing_recon(self):
        output = format_surface_output({"available": False}, "missing.com")
        assert "No recon data found for missing.com." in output

    def test_format_missing_recon_shows_cached_runtime_hint(self):
        output = format_surface_output(
            {
                "available": False,
                "runtime_state": {"last_executed_workflow": "run_recon", "mode": "recon_only"},
                "recon_artifacts": {"available": True, "missing": ["recon directory"], "warnings": []},
            },
            "missing.com",
        )

        assert "Last workflow: run_recon" in output
        assert "Cached recon issue: recon directory" in output
