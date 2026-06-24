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

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import agent


def _build_dispatcher(tmp_path):
    memory = agent.HuntMemory(str(tmp_path / "agent_session.json"))
    return agent.ToolDispatcher("target.com", memory)


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
        for arg in ("endpoints_file", "js_intel", "max_requests", "add_default_seeds"):
            assert arg in props, f"missing arg {arg}"
        assert props["max_requests"]["type"] == "integer"
        assert props["add_default_seeds"]["type"] == "boolean"
        assert props["endpoints_file"]["type"] == "string"
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
        def fake_run_cmd(cmd, cwd=None, timeout=600):
            captured["cmd"] = cmd
            return True, ""
        monkeypatch.setattr(huntmod, "run_cmd", fake_run_cmd)

        ok = huntmod.run_json_inject_probe(target)
        assert ok is True
        # the wrapper auto-discovered xhr_endpoints.txt
        assert "xhr_endpoints.txt" in captured["cmd"]
        assert "--endpoints-file" in captured["cmd"]
        assert "--target auto-disc.test" in captured["cmd"]

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
        def fake_run_cmd(cmd, cwd=None, timeout=600):
            captured["cmd"] = cmd
            return True, ""
        monkeypatch.setattr(huntmod, "run_cmd", fake_run_cmd)

        huntmod.run_json_inject_probe(target)
        assert "hypotheses.json" in captured["cmd"]
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
        def fake_run_cmd(cmd, cwd=None, timeout=600):
            captured["cmd"] = cmd
            return True, ""
        monkeypatch.setattr(huntmod, "run_cmd", fake_run_cmd)

        huntmod.run_json_inject_probe(target, endpoints_file=str(custom))
        # explicit caller arg wins over auto-discovery
        assert str(custom) in captured["cmd"]
        assert "xhr_endpoints.txt" not in captured["cmd"]


# ---------------------------------------------------------------------
#  json_inject_probe self-contained sanity
# ---------------------------------------------------------------------

class TestProbeSelfContained:
    def test_probe_module_imports_cleanly(self):
        from tools import json_inject_probe
        assert hasattr(json_inject_probe, "main")
        assert hasattr(json_inject_probe, "probe_endpoint")
        assert hasattr(json_inject_probe, "_detect_hit")

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
