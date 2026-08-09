"""tests/test_json_inject_dispatcher.py — PR-1 wiring contract tests.

Verifies the AI-callable surgical POST-JSON injection probe is fully wired
into agent.py's ToolDispatcher:

  1. Tool name appears in TOOLS / TOOL_NAMES
  2. _OPTIONAL_TOOL_FUNCS maps tool_name → hunt.py function name
  3. _FINISH_FLOOR_PROGRESS_TOOLS includes it (counts as a substantive hunt step)
  4. Dispatcher branch invokes hunt.run_json_inject_probe with correct kwargs
  5. Tool spec JSON-schema is well-formed (LLM can introspect)
  6. The wrapper in tools/hunt.py auto-discovers default inputs
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import agent  # noqa: E402


def _build_dispatcher(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent_session.json"))
    return agent.ToolDispatcher("target.com", memory)


def test_json_probe_shares_one_request_budget_across_endpoints(monkeypatch):
    from tools import json_inject_probe as probe

    endpoints = [
        {"method": "POST", "url": f"https://target.test/api/{index}", "body_template": {"q": "x"}, "source": "test"}
        for index in range(3)
    ]
    allocated: list[int] = []
    captured: dict = {}

    class Session:
        def bind_target(self, _target):
            return self

        def is_empty(self):
            return True

        def headers_for_url(self, _url):
            return {}

        def session_id(self):
            return ""

    def fake_probe(_endpoint, max_requests, *, stats, **_kwargs):
        allocated.append(max_requests)
        stats["request_count"] += max_requests
        return [], []

    def fake_write(_target, _hits, _events, *, execution):
        captured.update(execution)
        return {"out_dir": "", "summary": "", "files": []}

    monkeypatch.setattr(probe, "session_from_args", lambda _args: Session())
    monkeypatch.setattr(probe, "_collect_endpoints", lambda _args: (endpoints, {
        "out_of_scope": 0, "unsupported_method": 0, "invalid_url": 0, "items": []
    }))
    monkeypatch.setattr(probe, "probe_endpoint", fake_probe)
    monkeypatch.setattr(probe, "_write_findings", fake_write)
    monkeypatch.setattr(sys, "argv", ["json_inject_probe", "--target", "target.test", "--max-requests", "6"])

    assert probe.main() == 0
    assert allocated == [2, 2, 2]
    assert captured["request_count"] == captured["request_budget"] == 6
    assert captured["budget_exhausted"] is True


def test_json_probe_resumes_endpoint_tail_and_keeps_prior_hit(monkeypatch, tmp_path):
    from tools import json_inject_probe as probe

    endpoints = [
        {"method": "POST", "url": f"https://target.test/api/{index}", "body_template": {"q": "x"}, "source": "test"}
        for index in range(4)
    ]
    calls: list[str] = []

    class Session:
        def bind_target(self, _target):
            return self

        def is_empty(self):
            return True

        def headers_for_url(self, _url):
            return {}

        def session_id(self):
            return ""

    def fake_probe(endpoint, max_requests, *, stats, **_kwargs):
        calls.append(endpoint["url"])
        stats["request_count"] += max_requests
        if endpoint["url"].endswith("/0"):
            return [{
                "url": endpoint["url"], "field": "q", "payload_class": "sqli_error",
                "signal": "sql_error",
            }], []
        return [], []

    monkeypatch.setattr(probe, "BASE_DIR", tmp_path)
    monkeypatch.setattr(probe, "session_from_args", lambda _args: Session())
    monkeypatch.setattr(probe, "_collect_endpoints", lambda _args: (endpoints, {
        "out_of_scope": 0, "unsupported_method": 0, "invalid_url": 0, "items": []
    }))
    monkeypatch.setattr(probe, "probe_endpoint", fake_probe)
    monkeypatch.setattr(sys, "argv", ["json_inject_probe", "--target", "target.test", "--max-requests", "2"])

    assert probe.main() == 0
    assert calls == [item["url"] for item in endpoints[:2]]
    summary_path = tmp_path / "findings" / "target.test" / "poc" / "json_inject" / "summary.json"
    first = json.loads(summary_path.read_text(encoding="utf-8"))
    assert first["cursor"]["next_endpoint_index"] == 2
    assert first["cursor"]["coverage_complete"] is False
    hit_path = tmp_path / "findings" / "target.test" / "poc" / "json_inject" / "sqli_error_api_0_q.json"
    assert hit_path.is_file()

    assert probe.main() == 0
    assert calls == [item["url"] for item in endpoints]
    second = json.loads(summary_path.read_text(encoding="utf-8"))
    assert second["resumed"] is True
    assert second["cursor"]["coverage_complete"] is True
    assert second["hit_count"] == 1
    assert hit_path.is_file()

    reset = probe._probe_cursor(
        summary_path,
        target="target.test",
        input_fingerprint="0" * 64,
        endpoint_count=len(endpoints),
        kind="json_inject_summary",
    )
    assert reset["resumed"] is False
    assert reset["start_index"] == 0


def test_json_probe_deep_budget_expands_after_waf_observation(monkeypatch, tmp_path):
    from tools import json_inject_probe as probe

    endpoints = [
        {"method": "POST", "url": f"https://target.test/api/{index}", "body_template": {"q": "x"}, "source": "test"}
        for index in range(2)
    ]
    allocated: list[int] = []
    captured: dict = {}

    class Session:
        def bind_target(self, _target):
            return self

        def is_empty(self):
            return True

        def headers_for_url(self, _url):
            return {}

        def session_id(self):
            return ""

    def fake_probe(_endpoint, max_requests, *, stats, **_kwargs):
        allocated.append(max_requests)
        stats["request_count"] += max_requests
        return [], [{"variant_source": "ai", "reason": "waf"}]

    def fake_write(_target, _hits, _events, *, execution):
        captured.update(execution)
        return {"out_dir": "", "summary": "", "files": []}

    monkeypatch.setattr(probe, "BASE_DIR", tmp_path)
    monkeypatch.setattr(probe, "session_from_args", lambda _args: Session())
    monkeypatch.setattr(probe, "_collect_endpoints", lambda _args: (endpoints, {
        "out_of_scope": 0, "unsupported_method": 0, "invalid_url": 0, "items": []
    }))
    monkeypatch.setattr(probe, "probe_endpoint", fake_probe)
    monkeypatch.setattr(probe, "_write_findings", fake_write)
    monkeypatch.setattr(sys, "argv", [
        "json_inject_probe", "--target", "target.test", "--max-requests", "2", "--deep",
    ])

    assert probe.main() == 0
    assert allocated[0] == 2
    assert allocated[1] > allocated[0]
    assert captured["budget"]["adaptive"] is True
    assert captured["request_budget"] > 2
    assert captured["request_count"] == sum(allocated)
    assert captured["request_count"] <= captured["request_budget"]


def test_json_resume_does_not_inflate_replayed_hit_count(monkeypatch, tmp_path):
    from tools import json_inject_probe as probe

    monkeypatch.setattr(probe, "BASE_DIR", tmp_path)
    hit = {"url": "https://target.test/api", "field": "q", "payload_class": "sqli_error", "signal": "sql_error"}
    base = {
        "input_fingerprint": "a" * 64,
        "endpoint_count": 1,
        "probed_endpoint_count": 1,
        "request_count": 1,
        "request_budget": 1,
        "budget_exhausted": True,
        "cursor": {"coverage_complete": False},
        "skipped": {},
    }
    probe._write_findings("target.test", [hit], [], execution=base)
    resumed = dict(base, resumed=True, request_count=2)
    result = probe._write_findings("target.test", [hit], [], execution=resumed)
    summary = json.loads(Path(result["summary"]).read_text(encoding="utf-8"))
    assert summary["hit_count"] == 1


# ---------------------------------------------------------------------
#  Hook 1 — TOOL_NAMES / TOOLS spec presence
# ---------------------------------------------------------------------

class TestToolRegistration:
    def test_tool_name_present_in_TOOL_NAMES(self):
        assert "run_json_inject_probe" in agent.TOOL_NAMES

    def test_tool_spec_present_in_TOOLS(self):
        names = {t["function"]["name"] for t in agent.TOOLS}
        assert "run_json_inject_probe" in names

    def test_tool_spec_is_well_formed(self):
        spec = next(
            t for t in agent.TOOLS
            if t["function"]["name"] == "run_json_inject_probe"
        )
        assert spec["type"] == "function"
        fn = spec["function"]
        assert "description" in fn
        assert "parameters" in fn
        params = fn["parameters"]
        assert params["type"] == "object"
        props = params["properties"]
        # All 4 documented args present and typed
        for arg in ("endpoints_file", "js_intel", "max_requests", "add_default_seeds", "waf_plan"):
            assert arg in props, f"missing arg {arg}"
        assert props["max_requests"]["type"] == "integer"
        assert props["add_default_seeds"]["type"] == "boolean"
        assert props["endpoints_file"]["type"] == "string"
        assert props["waf_plan"]["type"] == "string"
        # No required args (auto-discovery covers them)
        assert params["required"] == []

    def test_description_mentions_post_json_and_payload_classes(self):
        spec = next(
            t for t in agent.TOOLS
            if t["function"]["name"] == "run_json_inject_probe"
        )
        desc = spec["function"]["description"].lower()
        # Must hint to LLM what it does and when to use it
        assert "post" in desc and "json" in desc
        assert "sqli" in desc
        assert "ssti" in desc or "cmd" in desc  # at least one other class
        assert "waf" in desc and "maximum eight" in desc and "capped at two" in desc


# ---------------------------------------------------------------------
#  Hook 2 — _OPTIONAL_TOOL_FUNCS mapping
# ---------------------------------------------------------------------

class TestOptionalToolMapping:
    def test_mapping_exists(self):
        # Find HuntModule-like wrapper class
        h = agent._h()
        assert "run_json_inject_probe" in h._OPTIONAL_TOOL_FUNCS
        assert h._OPTIONAL_TOOL_FUNCS["run_json_inject_probe"] == "run_json_inject_probe"

    def test_hunt_module_exposes_function(self):
        h = agent._h()
        assert hasattr(h._module, "run_json_inject_probe")
        assert callable(h._module.run_json_inject_probe)

    def test_supported_tool_names_includes_probe(self):
        h = agent._h()
        assert "run_json_inject_probe" in h.supported_tool_names()


# ---------------------------------------------------------------------
#  Hook 3 — _FINISH_FLOOR_PROGRESS_TOOLS membership
# ---------------------------------------------------------------------

class TestFinishFloorMembership:
    def test_probe_counts_as_progress(self):
        # finish gate needs ≥2 substantive hunt steps; the probe should qualify
        assert "run_json_inject_probe" in agent._FINISH_FLOOR_PROGRESS_TOOLS

    def test_finish_floor_count_helper_picks_up_probe(self):
        count = agent._finish_floor_progress_count(
            ["run_recon", "run_json_inject_probe"]
        )
        assert count == 2


# ---------------------------------------------------------------------
#  Hook 4 — Dispatcher branch invokes the wrapper
# ---------------------------------------------------------------------

class TestDispatcherBranch:
    def test_dispatch_invokes_wrapper_with_defaults(self, monkeypatch, tmp_path):
        captured = {}
        def fake_probe(domain, **kwargs):
            captured["domain"] = domain
            captured.update(kwargs)
            return True

        hunt = agent._h()
        monkeypatch.setattr(hunt, "run_json_inject_probe", fake_probe)

        dispatcher = _build_dispatcher(tmp_path)
        obs = dispatcher.dispatch("run_json_inject_probe", {})

        assert captured["domain"] == "target.com"
        # default values from spec
        assert captured["endpoints_file"] == ""
        assert captured["js_intel"] == ""
        assert captured["max_requests"] == 60
        assert captured["add_default_seeds"] is True
        assert captured["waf_plan"] == ""
        # observation summary contains the json_inject label
        assert "json_inject" in obs

    def test_dispatch_forwards_custom_args(self, monkeypatch, tmp_path):
        captured = {}
        def fake_probe(domain, **kwargs):
            captured.update(kwargs)
            return True

        hunt = agent._h()
        monkeypatch.setattr(hunt, "run_json_inject_probe", fake_probe)

        dispatcher = _build_dispatcher(tmp_path)
        dispatcher.dispatch("run_json_inject_probe", {
            "endpoints_file": "/tmp/eps.txt",
            "js_intel": "/tmp/hyp.json",
            "max_requests": 25,
            "add_default_seeds": False,
        })

        assert captured["endpoints_file"] == "/tmp/eps.txt"
        assert captured["js_intel"] == "/tmp/hyp.json"
        assert captured["max_requests"] == 25
        assert captured["add_default_seeds"] is False

        captured.clear()
        dispatcher.dispatch("run_json_inject_probe", {"waf_plan": "/tmp/plan.json"})
        assert captured["waf_plan"] == "/tmp/plan.json"

    def test_dispatch_coerces_max_requests_to_int(self, monkeypatch, tmp_path):
        captured = {}
        def fake_probe(domain, **kwargs):
            captured.update(kwargs)
            return True

        hunt = agent._h()
        monkeypatch.setattr(hunt, "run_json_inject_probe", fake_probe)

        dispatcher = _build_dispatcher(tmp_path)
        dispatcher.dispatch("run_json_inject_probe", {"max_requests": "42"})
        assert captured["max_requests"] == 42


# ---------------------------------------------------------------------
#  Hook 5 — Wrapper auto-discovery of default inputs
# ---------------------------------------------------------------------

class TestWrapperAutoDiscovery:
    def test_wrapper_auto_loads_xhr_endpoints_when_present(self, monkeypatch, tmp_path):
        from tools import hunt as huntmod
        # Sandbox path constants used by _resolve_*_dir
        monkeypatch.setattr(huntmod, "BASE_DIR", str(tmp_path))
        monkeypatch.setattr(huntmod, "RECON_DIR", str(tmp_path / "recon"))
        monkeypatch.setattr(huntmod, "FINDINGS_DIR", str(tmp_path / "findings"))

        target = "auto-disc.test"
        recon_dir = tmp_path / "recon" / target / "browser"
        recon_dir.mkdir(parents=True)
        xhr = recon_dir / "xhr_endpoints.txt"
        xhr.write_text("https://auto-disc.test/api/login\n")

        captured = {}
        def fake_run_argv(cmd, cwd=None, timeout=600, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return True, ""
        monkeypatch.setattr(huntmod, "run_argv", fake_run_argv)

        ok = huntmod.run_json_inject_probe(target)
        assert ok is True
        # the wrapper auto-discovered xhr_endpoints.txt
        assert any("xhr_endpoints.txt" in value for value in captured["cmd"])
        assert "--endpoints-file" in captured["cmd"]
        assert captured["cmd"][captured["cmd"].index("--target") + 1] == "auto-disc.test"

    def test_wrapper_auto_loads_js_intel_when_present(self, monkeypatch, tmp_path):
        from tools import hunt as huntmod
        monkeypatch.setattr(huntmod, "BASE_DIR", str(tmp_path))
        monkeypatch.setattr(huntmod, "RECON_DIR", str(tmp_path / "recon"))
        monkeypatch.setattr(huntmod, "FINDINGS_DIR", str(tmp_path / "findings"))

        target = "auto-js.test"
        ji_dir = tmp_path / "findings" / target / "js_intel"
        ji_dir.mkdir(parents=True)
        (ji_dir / "hypotheses.json").write_text('{"endpoints": {"rest_custom": []}}')

        captured = {}
        def fake_run_argv(cmd, cwd=None, timeout=600, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return True, ""
        monkeypatch.setattr(huntmod, "run_argv", fake_run_argv)

        huntmod.run_json_inject_probe(target)
        assert any("hypotheses.json" in value for value in captured["cmd"])
        assert "--js-intel" in captured["cmd"]

    def test_wrapper_respects_explicit_overrides(self, monkeypatch, tmp_path):
        from tools import hunt as huntmod
        monkeypatch.setattr(huntmod, "BASE_DIR", str(tmp_path))
        monkeypatch.setattr(huntmod, "RECON_DIR", str(tmp_path / "recon"))
        monkeypatch.setattr(huntmod, "FINDINGS_DIR", str(tmp_path / "findings"))

        target = "explicit.test"
        # Also create an auto-discoverable file — but caller overrides it
        recon_dir = tmp_path / "recon" / target / "browser"
        recon_dir.mkdir(parents=True)
        (recon_dir / "xhr_endpoints.txt").write_text("https://x/old\n")

        custom = tmp_path / "custom_eps.txt"
        custom.write_text("https://x/new\n")

        captured = {}
        def fake_run_argv(cmd, cwd=None, timeout=600, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return True, ""
        monkeypatch.setattr(huntmod, "run_argv", fake_run_argv)

        huntmod.run_json_inject_probe(target, endpoints_file=str(custom))
        # explicit caller arg wins over auto-discovery
        assert str(custom) in captured["cmd"]
        assert not any("xhr_endpoints.txt" in value for value in captured["cmd"])

    def test_wrapper_can_disable_default_seeds(self, monkeypatch, tmp_path):
        from tools import hunt as huntmod

        monkeypatch.setattr(huntmod, "BASE_DIR", str(tmp_path))
        monkeypatch.setattr(huntmod, "RECON_DIR", str(tmp_path / "recon"))
        monkeypatch.setattr(huntmod, "FINDINGS_DIR", str(tmp_path / "findings"))
        captured = {}

        def fake_run_argv(cmd, cwd=None, timeout=600, env=None):
            captured["cmd"] = cmd
            captured["env"] = env
            return True, ""

        monkeypatch.setattr(huntmod, "run_argv", fake_run_argv)

        assert huntmod.run_json_inject_probe("strict.test", add_default_seeds=False) is True
        assert "--no-default-seeds" in captured["cmd"]

    def test_wrapper_forwards_deep_budget_flag(self, monkeypatch, tmp_path):
        from tools import hunt as huntmod

        monkeypatch.setattr(huntmod, "BASE_DIR", str(tmp_path))
        monkeypatch.setattr(huntmod, "RECON_DIR", str(tmp_path / "recon"))
        monkeypatch.setattr(huntmod, "FINDINGS_DIR", str(tmp_path / "findings"))
        captured = {}

        def fake_run_argv(cmd, cwd=None, timeout=600, env=None):
            captured["cmd"] = cmd
            return True, ""

        monkeypatch.setattr(huntmod, "run_argv", fake_run_argv)
        assert huntmod.run_json_inject_probe("deep.test", deep=True) is True
        assert "--deep" in captured["cmd"]


# ---------------------------------------------------------------------
#  json_inject_probe self-contained sanity
# ---------------------------------------------------------------------

class TestProbeSelfContained:
    def test_probe_module_imports_cleanly(self):
        from tools import json_inject_probe
        assert hasattr(json_inject_probe, "main")
        assert hasattr(json_inject_probe, "probe_endpoint")
        assert hasattr(json_inject_probe, "_detect_hit")

    def test_cli_no_default_seeds_requires_an_input(self, monkeypatch):
        from tools import json_inject_probe

        monkeypatch.setattr(
            sys,
            "argv",
            ["json_inject_probe", "--target", "strict.test", "--no-default-seeds"],
        )
        assert json_inject_probe.main() == 1

    def test_endpoint_collection_rejects_off_target_and_non_post_before_network(self, tmp_path):
        from tools import json_inject_probe as probe

        endpoints = tmp_path / "endpoints.jsonl"
        endpoints.write_text(
            "\n".join([
                '{"method":"POST","url":"https://api.target.test/login","body":{"x":"y"}}',
                '{"method":"GET","url":"https://target.test/read","body":{"x":"y"}}',
                '{"method":"POST","url":"https://third-party.test/login","body":{"x":"y"}}',
            ]),
            encoding="utf-8",
        )
        args = argparse.Namespace(
            target="target.test",
            endpoints_file=str(endpoints),
            js_intel="",
            add_default_seeds=False,
        )

        accepted, skipped = probe._collect_endpoints(args)

        assert [item["url"] for item in accepted] == ["https://api.target.test/login"]
        assert skipped["unsupported_method"] == 1
        assert skipped["out_of_scope"] == 1

    def test_redirect_handler_stops_before_following_off_target_url(self):
        from tools import json_inject_probe as probe

        handler = probe._ScopedRedirectHandler("target.test")

        with pytest.raises(probe.OutOfScopeRedirect, match="third-party.test"):
            handler.redirect_request(
                urllib.request.Request("https://target.test/start"),
                None,
                302,
                "Found",
                {},
                "https://third-party.test/callback?token=secret",
            )

    def test_http_post_applies_scoped_auth_without_logging_it(self, monkeypatch):
        from tools import json_inject_probe as probe
        from tools.auth_session import AuthSession

        captured = {}

        class Response:
            status = 200
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"{}"

        class Opener:
            def open(self, request, timeout=None):
                captured["headers"] = dict(request.header_items())
                return Response()

        monkeypatch.setattr(probe.urllib.request, "build_opener", lambda *_handlers: Opener())
        session = AuthSession(["Authorization: Bearer secret"], target="target.test")

        result = probe._http_post_json(
            "https://target.test/login",
            {"user": "a"},
            target="target.test",
            session=session,
        )

        assert captured["headers"]["Authorization"] == "Bearer secret"
        assert "secret" not in json.dumps(result)

    def test_structured_summary_is_returned_to_agent(self, monkeypatch, tmp_path):
        hunt = agent._h()
        findings_dir = tmp_path / "findings"
        monkeypatch.setattr(hunt, "FINDINGS_DIR", str(findings_dir))
        summary_dir = findings_dir / "target.com" / "poc" / "json_inject"
        summary_dir.mkdir(parents=True)
        (summary_dir / "summary.json").write_text(
            '{"hit_count": 2, "waf_observation_count": 3, '
            '"waf_observations": [{"outcome": "waf_blocked"}, '
            '{"outcome": "application_response"}, {"outcome": "waf_blocked"}]}',
            encoding="utf-8",
        )

        summary = _build_dispatcher(tmp_path)._summarize_findings("target.com", "json_inject", True)

        assert "hits=2 waf_observations=3" in summary
        assert "application_response:1" in summary
        assert "waf_blocked:2" in summary

    def test_payload_library_has_all_11_classes(self):
        from tools.json_inject_probe import PAYLOADS
        classes = {p["class"] for p in PAYLOADS}
        expected = {
            "sqli_auth_bypass", "sqli_error", "sqli_time",
            "ssti", "cmd_injection", "open_redirect",
            "path_traversal", "xss",
            # PR-3 additions
            "nosql_op_injection", "nosql_regex_bypass",
            "graphql_introspection",
        }
        assert expected.issubset(classes)

    def test_payload_library_covers_expanded_sql_families(self):
        from tools.json_inject_probe import PAYLOADS

        values = {str(item["value"]) for item in PAYLOADS if str(item["class"]).startswith("sqli_")}
        expected = {
            "' Or 1=1 AND '1'='1",
            "' Or 1=2 AND '1'='1",
            "'||1/1||'",
            "'||1/0||'",
            "'%df' and sleep(3)#",
            "+AND 1=1",
            "+AND sleep(5)",
            "1');SELECT SLEEP(5)#",
            "(SELECT 6242 FROM (SELECT(SLEEP(5)))MgdE)",
        }
        assert expected.issubset(values)
        assert {"boolean_pair", "arithmetic", "time_based", "waf_bypass"}.issubset(
            {str(item.get("family")) for item in PAYLOADS if str(item["class"]).startswith("sqli_")}
        )

    def test_short_sql_time_probe_uses_its_declared_threshold(self):
        from tools.json_inject_probe import _detect_hit

        baseline = {"body_text": "{}", "latency": 0.1, "status": 200}
        response = {"body_text": "{}", "latency": 2.8, "status": 200}
        assert _detect_hit("sqli_time", baseline, response, "'%df' and sleep(3)#", min_delay=2.5)["hit"]

    def test_payload_plan_puts_each_class_before_deep_variants(self):
        from tools.json_inject_probe import PAYLOADS, _payload_plan

        class_count = len({str(item["class"]) for item in PAYLOADS})
        first_classes = {str(item["class"]) for item in _payload_plan()[:class_count]}
        assert first_classes == {str(item["class"]) for item in PAYLOADS}

    def test_payload_field_plan_reserves_classes_on_wide_json_bodies(self):
        from tools.json_inject_probe import PAYLOADS, _payload_field_plan

        body = {
            "login": "x",
            "query": "x",
            "host": "x",
            "url": "x",
            "path": "x",
            "value": "x",
        }
        class_count = len({str(item["class"]) for item in PAYLOADS})
        first_classes = {
            str(payload["class"])
            for payload, _field in _payload_field_plan(body)[:class_count]
        }

        assert len(first_classes) == class_count

    def test_boolean_pair_difference_is_promoted_after_both_sides(self, monkeypatch):
        from tools import json_inject_probe as probe

        def response(body):
            return {
                "status": 200,
                "body_text": body,
                "body_size": len(body),
                "headers": "",
                "latency": 0.05,
                "error": None,
            }

        monkeypatch.setattr(probe, "PAYLOADS", [
            {
                "class": "sqli_boolean_true",
                "family": "boolean_pair",
                "pair_id": "test-pair",
                "pair_side": "true",
                "value": "' AND 1=1--",
                "field_hint": ".*",
            },
            {
                "class": "sqli_boolean_false",
                "family": "boolean_pair",
                "pair_id": "test-pair",
                "pair_side": "false",
                "value": "' AND 1=2--",
                "field_hint": ".*",
            },
        ])
        responses = iter([
            response('{"ok":true,"items":[1,2]}'),
            response('{"ok":true,"items":[1,2]}'),
            response('{"ok":false}'),
        ])
        monkeypatch.setattr(probe, "_http_post_json", lambda *args, **kwargs: next(responses))

        hits, _ = probe.probe_endpoint(
            {"url": "https://target.test/search", "body_template": {"q": "x"}},
            max_requests=6,
        )

        assert len(hits) == 1
        assert hits[0]["payload_class"] == "sqli_boolean_pair"
        assert hits[0]["signal"] == "sqli_boolean_pair_difference"

    def test_nosql_payloads_are_dict_typed(self):
        """NoSQL operator/regex payloads must carry a dict value so the
        outgoing JSON body re-shapes the field from string → object."""
        from tools.json_inject_probe import PAYLOADS
        nosql = {p["class"]: p for p in PAYLOADS
                 if p["class"].startswith("nosql_")}
        assert isinstance(nosql["nosql_op_injection"]["value"], dict)
        assert isinstance(nosql["nosql_regex_bypass"]["value"], dict)
        assert nosql["nosql_op_injection"]["value"] == {"$ne": None}
        assert nosql["nosql_regex_bypass"]["value"] == {"$regex": ".*"}

    def test_graphql_payload_targets_query_field(self):
        from tools.json_inject_probe import PAYLOADS
        gql = next(p for p in PAYLOADS if p["class"] == "graphql_introspection")
        # The hint must restrict probing to graphql-shaped field names
        assert "query" in gql["field_hint"]
        assert "__schema" in gql["value"]

    def test_nosql_op_injection_triggers_jwt_auth_bypass_signal(self):
        """JWT in response + payload_class=nosql_op_injection fires signal A."""
        from tools.json_inject_probe import _detect_hit
        baseline = {"body_text": '{"error":"unauthorized"}', "latency": 0.05, "status": 401}
        resp = {
            "body_text": '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.xxxxxxxx"}',
            "latency": 0.08, "status": 200,
        }
        out = _detect_hit("nosql_op_injection", baseline, resp, {"$ne": None})
        assert out["hit"] is True
        assert out["signal"] == "nosql_op_injection_jwt_returned"
        assert "jwt_prefix=" in out["evidence"]

    def test_nosql_regex_bypass_triggers_jwt_auth_bypass_signal(self):
        from tools.json_inject_probe import _detect_hit
        baseline = {"body_text": '{"error":"bad creds"}', "latency": 0.05, "status": 401}
        resp = {
            "body_text": '{"jwt":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCJ9.zzzzzzzz"}',
            "latency": 0.08, "status": 200,
        }
        out = _detect_hit("nosql_regex_bypass", baseline, resp, {"$regex": ".*"})
        assert out["hit"] is True
        assert out["signal"] == "nosql_regex_bypass_jwt_returned"

    def test_graphql_introspection_hit_requires_baseline_clean(self):
        """Introspection signal fires when markers appear in probe response
        but were absent in baseline (avoids playground false-positives)."""
        from tools.json_inject_probe import _detect_hit
        baseline = {"body_text": '{"error":"missing query"}', "latency": 0.05, "status": 400}
        # Plausible Apollo/Yoga introspection result
        resp = {
            "body_text": '{"data":{"__schema":{"types":[{"name":"User"},{"name":"Query"}]}}}',
            "latency": 0.06, "status": 200,
        }
        out = _detect_hit("graphql_introspection", baseline, resp, "{ __schema { types { name } } }")
        assert out["hit"] is True
        assert out["signal"] == "graphql_introspection_enabled"
        assert "introspection marker present" in out["evidence"]

    def test_graphql_introspection_no_hit_when_baseline_also_has_marker(self):
        """If baseline already contains __schema (e.g. playground page),
        the introspection probe must not fire — baseline diff required."""
        from tools.json_inject_probe import _detect_hit
        baseline = {"body_text": 'GraphQL playground __schema docs', "latency": 0.04, "status": 200}
        resp = {"body_text": 'GraphQL playground __schema docs', "latency": 0.05, "status": 200}
        out = _detect_hit("graphql_introspection", baseline, resp, "{ __schema { types { name } } }")
        assert out["hit"] is False

    def test_sqli_auth_bypass_signal_label_unchanged(self):
        """Existing SQLi auth-bypass label is preserved (no rename)."""
        from tools.json_inject_probe import _detect_hit
        baseline = {"body_text": '{"error":"bad creds"}', "latency": 0.05, "status": 401}
        resp = {
            "body_text": '{"jwt":"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.yyyyyyyy"}',
            "latency": 0.08, "status": 200,
        }
        out = _detect_hit("sqli_auth_bypass", baseline, resp, "' OR 1=1--")
        assert out["hit"] is True
        assert out["signal"] == "auth_bypass_jwt_returned"  # NOT renamed


class TestAdaptiveWafVariants:
    @staticmethod
    def response(status=200, body="{}", headers="", latency=0.05):
        return {
            "status": status,
            "body_text": body,
            "body_size": len(body),
            "headers": headers,
            "latency": latency,
            "error": None,
        }

    def test_waf_detection_is_relative_to_endpoint_baseline(self):
        from tools.json_inject_probe import _waf_observation

        baseline = self.response(headers="Server: cloudflare\nCF-Ray: base")
        ordinary = self.response(headers="Server: cloudflare\nCF-Ray: probe")
        blocked = self.response(
            status=403,
            body="Sorry, you have been blocked. Cloudflare Ray ID: abcdef123456",
            headers="Server: cloudflare\nCF-Ray: blocked",
        )

        assert _waf_observation(baseline, ordinary)["blocked"] is False
        observation = _waf_observation(baseline, blocked)
        assert observation["blocked"] is True
        assert "block_status_delta" in observation["signals"]

    def test_transport_failures_and_plain_rate_limits_are_not_waf_blocks(self):
        from tools.json_inject_probe import _detect_hit, _waf_observation

        baseline = self.response()
        rate_limited = self.response(status=429, body="too many requests")
        failed = self.response(status=0, latency=8.0)
        failed["error"] = "TimeoutError:timed out"

        assert _waf_observation(baseline, rate_limited)["outcome"] == "rate_limited"
        assert _waf_observation(baseline, failed)["outcome"] == "transport_error"
        assert _detect_hit("sqli_time", baseline, failed, "1' AND SLEEP(5)-- -")["hit"] is False

    def test_failed_baseline_stops_endpoint_probing(self, monkeypatch):
        from tools import json_inject_probe as probe

        failed = self.response(status=0)
        failed["error"] = "TimeoutError:timed out"
        calls = []

        def fake_post(url, body, timeout=10.0):
            calls.append(body)
            return failed

        monkeypatch.setattr(probe, "_http_post_json", fake_post)
        assert probe.probe_endpoint(
            {"url": "https://target.test/login", "body_template": {"email": "a@b.test"}},
            max_requests=10,
        ) == ([], [])
        assert len(calls) == 1

    def test_blocked_sqli_retries_bounded_variant_and_can_hit(self, monkeypatch):
        from tools import json_inject_probe as probe

        monkeypatch.setattr(probe, "PAYLOADS", [
            {"class": "sqli_auth_bypass", "value": "' OR 1=1--", "field_hint": ".*"},
        ])
        responses = iter([
            self.response(status=401, body='{"error":"bad creds"}'),
            self.response(status=403, body="Access Denied", headers="Server: cloudflare\nCF-Ray: blocked"),
            self.response(status=500, body="SQL syntax error near OR"),
        ])
        calls = []

        def fake_post(url, body, timeout=10.0):
            calls.append(body)
            return next(responses)

        monkeypatch.setattr(probe, "_http_post_json", fake_post)
        hits, waf_events = probe.probe_endpoint(
            {"url": "https://target.test/login", "body_template": {"email": "a@b.test"}},
            max_requests=10,
        )

        assert len(calls) == 3
        assert hits[0]["signal"] == "sql_error_fingerprint"
        assert hits[0]["waf_variant"] == "space-to-/**/-comment"
        assert waf_events[0]["blocked"] is True
        assert waf_events[-1]["blocked"] is False

    def test_normal_response_does_not_expand_payload(self, monkeypatch):
        from tools import json_inject_probe as probe

        monkeypatch.setattr(probe, "PAYLOADS", [
            {"class": "sqli_auth_bypass", "value": "' OR 1=1--", "field_hint": ".*"},
        ])
        calls = []

        def fake_post(url, body, timeout=10.0):
            calls.append(body)
            return self.response(status=401, body='{"error":"bad creds"}')

        monkeypatch.setattr(probe, "_http_post_json", fake_post)
        hits, waf_events = probe.probe_endpoint(
            {"url": "https://target.test/login", "body_template": {"email": "a@b.test"}},
            max_requests=10,
        )

        assert len(calls) == 2
        assert hits == []
        assert waf_events == []

    def test_nosql_objects_are_not_encoded_and_limit_includes_retries(self, monkeypatch):
        from tools import json_inject_probe as probe

        monkeypatch.setattr(probe, "PAYLOADS", [
            {"class": "nosql_op_injection", "value": {"$ne": None}, "field_hint": ".*"},
        ])
        calls = []

        def fake_post(url, body, timeout=10.0):
            calls.append(body)
            if len(calls) == 1:
                return self.response(status=401, body='{"error":"bad creds"}')
            return self.response(status=403, body="Access Denied")

        monkeypatch.setattr(probe, "_http_post_json", fake_post)
        _, waf_events = probe.probe_endpoint(
            {"url": "https://target.test/login", "body_template": {"email": "a@b.test"}},
            max_requests=2,
        )

        assert len(calls) == 2
        assert calls[-1]["email"] == {"$ne": None}
        assert len(waf_events) == 1

    def test_blocked_xss_uses_class_specific_variant(self, monkeypatch):
        from tools import json_inject_probe as probe

        monkeypatch.setattr(probe, "PAYLOADS", [
            {"class": "xss", "value": "<svg/onload=alert(1)>", "field_hint": ".*"},
        ])
        calls = []

        def fake_post(url, body, timeout=10.0):
            calls.append(body)
            if len(calls) == 1:
                return self.response(body='{"value":"clean"}')
            if len(calls) == 2:
                return self.response(status=403, body="Access Denied")
            return self.response(body=body["comment"])

        monkeypatch.setattr(probe, "_http_post_json", fake_post)
        hits, _ = probe.probe_endpoint(
            {"url": "https://target.test/comment", "body_template": {"comment": "clean"}},
            max_requests=10,
        )

        assert len(calls) == 3
        assert hits[0]["signal"] == "xss_reflection"
        assert hits[0]["waf_variant"] == "xss-base64-svg-onload"

    def test_retry_transport_error_stops_without_a_hit(self, monkeypatch):
        from tools import json_inject_probe as probe

        monkeypatch.setattr(probe, "PAYLOADS", [
            {"class": "sqli_time", "value": "1' AND SLEEP(5)-- -", "field_hint": ".*"},
        ])
        failed = self.response(status=0, latency=8.0)
        failed["error"] = "TimeoutError:timed out"
        responses = iter([
            self.response(),
            self.response(status=403, body="Access Denied"),
            failed,
        ])
        calls = []

        def fake_post(url, body, timeout=10.0):
            calls.append(body)
            return next(responses)

        monkeypatch.setattr(probe, "_http_post_json", fake_post)
        hits, observations = probe.probe_endpoint(
            {"url": "https://target.test/search", "body_template": {"q": "x"}},
            max_requests=10,
        )

        assert len(calls) == 3
        assert hits == []
        assert observations[-1]["outcome"] == "transport_error"

    def test_block_page_content_cannot_be_promoted_to_a_hit(self, monkeypatch):
        from tools import json_inject_probe as probe

        monkeypatch.setattr(probe, "PAYLOADS", [
            {"class": "sqli_error", "value": "'", "field_hint": ".*"},
        ])
        responses = iter([
            self.response(),
            self.response(status=403, body="Access Denied: SQL syntax was blocked"),
        ])
        monkeypatch.setattr(probe, "_http_post_json", lambda *args, **kwargs: next(responses))

        hits, observations = probe.probe_endpoint(
            {"url": "https://target.test/search", "body_template": {"q": "x"}},
            max_requests=10,
        )

        assert hits == []
        assert observations[0]["blocked"] is True

    def test_sql_variants_are_changed_and_bounded(self):
        from tools.json_inject_probe import _waf_variants

        assert _waf_variants("sqli_error", "'") == []
        variants = _waf_variants("sqli_auth_bypass", "' OR 1=1--")
        assert len(variants) == 2
        assert all(value != "' OR 1=1--" for _, value in variants)

    def test_waf_encoder_handles_multiple_sql_keywords_without_offset_drift(self):
        from tools.waf_encoder import sql_comment_inject

        variants = dict(sql_comment_inject("UNION SELECT id FROM users WHERE id=1 ORDER BY id"))
        split = variants["sql-comment-/**/-split"]
        assert split == "U/**/NION S/**/ELECT id F/**/ROM users W/**/HERE id=1 O/**/RDER BY id"

    def test_rerun_clears_stale_hit_files(self, monkeypatch, tmp_path):
        from tools import json_inject_probe as probe

        monkeypatch.setattr(probe, "BASE_DIR", tmp_path)
        out_dir = tmp_path / "findings" / "target.test" / "poc" / "json_inject"
        out_dir.mkdir(parents=True)
        stale = out_dir / "sqli_error_old.json"
        stale.write_text("{}", encoding="utf-8")

        result = probe._write_findings("target.test", [], [])

        assert not stale.exists()
        summary = Path(result["summary"])
        assert summary.is_file()
        assert "waf_observation_count" in summary.read_text(encoding="utf-8")

    def test_atomic_summary_failure_preserves_previous_bytes(self, monkeypatch, tmp_path):
        from tools import json_inject_probe as probe

        path = tmp_path / "summary.json"
        path.write_bytes(b'{"old":true}\n')
        monkeypatch.setattr(Path, "replace", lambda *_args: (_ for _ in ()).throw(OSError("replace failed")))

        with pytest.raises(OSError, match="replace failed"):
            probe._write_json_atomic(path, {"new": True})

        assert path.read_bytes() == b'{"old":true}\n'
        assert not list(tmp_path.glob(".summary.json.*.tmp"))

    def test_summary_keeps_counts_but_bounds_observation_arrays(self, monkeypatch, tmp_path):
        from tools import json_inject_probe as probe

        monkeypatch.setattr(probe, "BASE_DIR", tmp_path)
        hits = [{
            "url": "https://target.test/api",
            "field": "q",
            "payload_class": "sqli_error",
            "signal": "sql_error",
        }] * 101
        events = [{"url": "https://target.test/api", "outcome": "application_response"}] * 101

        result = probe._write_findings("target.test", hits, events)
        summary = json.loads(Path(result["summary"]).read_text(encoding="utf-8"))

        assert summary["hit_count"] == summary["waf_observation_count"] == 101
        assert len(summary["hits"]) == len(summary["waf_observations"]) == probe.SUMMARY_ITEM_LIMIT
