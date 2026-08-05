from __future__ import annotations

import json

import pytest


def _artifact(tmp_path):
    path = tmp_path / "recon" / "target.test" / "live" / "waf_context.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"kind":"waf_context"}\n', encoding="utf-8")
    return path


def _payload(artifact):
    return {
        "schema_version": 1,
        "target": "target.test",
        "evidence_refs": [str(artifact)],
        "max_variants": 2,
        "variants": [
            {
                "id": "comment-boundary",
                "payload_class": "sqli_auth_bypass",
                "endpoint": "https://target.test/login",
                "field": "email",
                "value": "'/**/OR/**/1=1--",
                "reason": "the observed block appears to split SQL keywords on spaces",
                "expected_signal": "application SQL error or stable auth response difference",
                "stop_condition": "same block response or a transport/rate-limit signal",
            }
        ],
    }


def test_plan_requires_existing_target_owned_evidence(tmp_path, monkeypatch):
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = waf_pass_plan.validate_plan(_payload(artifact), target="target.test")

    assert plan["variants"][0]["evidence_refs"] == ["recon/target.test/live/waf_context.json"]
    assert waf_pass_plan.select_variants(
        plan,
        url="https://target.test/login",
        payload_class="sqli_auth_bypass",
        field="email",
        canonical_value="' OR 1=1--",
    )[0]["id"] == "comment-boundary"

    bad = dict(_payload(artifact), evidence_refs=[str(tmp_path / "other.json")])
    with pytest.raises(ValueError, match="existing target artifact"):
        waf_pass_plan.validate_plan(bad, target="target.test")


def test_plan_rejects_scope_and_unbounded_variants(tmp_path, monkeypatch):
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = _payload(artifact)
    plan["variants"] = [dict(plan["variants"][0], id=f"v-{i}") for i in range(3)]
    with pytest.raises(ValueError, match="bounded list"):
        waf_pass_plan.validate_plan(plan, target="target.test")

    plan = _payload(artifact)
    plan["variants"][0]["endpoint"] = "https://other.test/login"
    with pytest.raises(ValueError, match="outside target scope"):
        waf_pass_plan.validate_plan(plan, target="target.test")


def test_plan_requires_target_and_strict_budget_types(tmp_path, monkeypatch):
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = _payload(artifact)
    plan.pop("target")
    with pytest.raises(ValueError, match="target is required"):
        waf_pass_plan.validate_plan(plan, target="target.test")

    plan = _payload(artifact)
    plan["max_variants"] = 2.0
    with pytest.raises(ValueError, match="max_variants.*integer"):
        waf_pass_plan.validate_plan(plan, target="target.test")

    plan = _payload(artifact)
    plan["max_requests"] = True
    with pytest.raises(ValueError, match="max_requests.*integer"):
        waf_pass_plan.validate_plan(plan, target="target.test")

    plan = _payload(artifact)
    plan["max_requests"] = None
    with pytest.raises(ValueError, match="max_requests.*integer"):
        waf_pass_plan.validate_plan(plan, target="target.test")

    plan = _payload(artifact)
    plan["budget"] = []
    with pytest.raises(ValueError, match="budget must be an object"):
        waf_pass_plan.validate_plan(plan, target="target.test")


def test_plan_rejects_duplicate_variant_values(tmp_path, monkeypatch):
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = _payload(artifact)
    plan["max_variants"] = 2
    plan["variants"].append(dict(plan["variants"][0], id="same-value"))
    with pytest.raises(ValueError, match="duplicates an earlier variant"):
        waf_pass_plan.validate_plan(plan, target="target.test")


def test_plan_rejects_non_string_optional_matchers(tmp_path, monkeypatch):
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    for field in ("field", "endpoint"):
        plan = _payload(artifact)
        plan["variants"][0][field] = []
        with pytest.raises(ValueError, match=f"variants\\[0\\]\\.{field}"):
            waf_pass_plan.validate_plan(plan, target="target.test")


def test_plan_accepts_structured_query_field_names(tmp_path, monkeypatch):
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = _payload(artifact)
    plan["variants"][0]["field"] = "filter[q]"
    normalized = waf_pass_plan.validate_plan(plan, target="target.test")
    assert normalized["variants"][0]["field"] == "filter[q]"


def test_plan_defaults_to_four_and_caps_at_eight(tmp_path, monkeypatch):
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = _payload(artifact)
    plan.pop("max_variants")
    assert waf_pass_plan.validate_plan(plan, target="target.test")["max_variants"] == 4

    plan["max_variants"] = 8
    plan["variants"] = [dict(plan["variants"][0], id=f"v-{i}", value=f"variant-{i}") for i in range(8)]
    assert len(waf_pass_plan.validate_plan(plan, target="target.test")["variants"]) == 8

    plan["variants"].append(dict(plan["variants"][0], id="v-8", value="variant-8"))
    with pytest.raises(ValueError, match="bounded list"):
        waf_pass_plan.validate_plan(plan, target="target.test")

    plan["max_variants"] = 9
    with pytest.raises(ValueError, match="between 1 and 8"):
        waf_pass_plan.validate_plan(plan, target="target.test")


def test_json_probe_records_ai_variant_after_relative_waf_block(tmp_path, monkeypatch):
    from tools import json_inject_probe as probe
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = waf_pass_plan.validate_plan(_payload(artifact), target="target.test")
    monkeypatch.setattr(probe, "PAYLOADS", [{
        "class": "sqli_auth_bypass",
        "value": "' OR 1=1--",
        "field_hint": ".*",
    }])
    responses = iter([
        {"status": 401, "body_text": '{"error":"bad"}', "body_size": 15, "headers": "", "latency": 0.05, "error": None},
        {"status": 403, "body_text": "Access Denied", "body_size": 12, "headers": "Server: cloudflare", "latency": 0.05, "error": None},
        {"status": 500, "body_text": "SQL syntax error near OR", "body_size": 25, "headers": "", "latency": 0.05, "error": None},
    ])
    monkeypatch.setattr(probe, "_http_post_json", lambda *args, **kwargs: next(responses))

    hits, events = probe.probe_endpoint(
        {"url": "https://target.test/login", "body_template": {"email": "a@b.test"}},
        max_requests=3,
        target="target.test",
        waf_plan=plan,
    )

    assert hits and hits[0]["variant_source"] == "ai"
    assert hits[0]["waf_variant_id"] == "comment-boundary"
    assert events[-1]["ai_reason"].startswith("the observed block")


def test_json_probe_without_plan_keeps_two_static_retries(monkeypatch):
    from tools import json_inject_probe as probe

    monkeypatch.setattr(probe, "PAYLOADS", [{
        "class": "sqli_auth_bypass",
        "value": "' OR 1=1--",
        "field_hint": ".*",
    }])
    blocked = {"status": 403, "body_text": "Access Denied", "body_size": 12, "headers": "Server: cloudflare", "latency": 0.05, "error": None}
    responses = iter([
        {"status": 401, "body_text": '{"error":"bad"}', "body_size": 15, "headers": "", "latency": 0.05, "error": None},
        blocked,
        blocked,
        blocked,
    ])
    calls = []
    monkeypatch.setattr(probe, "_http_post_json", lambda url, body, timeout=10.0, **_kwargs: calls.append(body) or next(responses))

    _, events = probe.probe_endpoint(
        {"url": "https://target.test/login", "body_template": {"email": "a@b.test"}},
        max_requests=8,
    )

    assert len(calls) == 4
    assert sum(event.get("variant_source") == "fallback" for event in events) == 2


def test_json_probe_plan_can_use_more_than_two_bounded_variants(tmp_path, monkeypatch):
    from tools import json_inject_probe as probe
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = _payload(artifact)
    plan["max_variants"] = 4
    plan["variants"] = [
        dict(plan["variants"][0], id=f"v-{index}", value=f"ai-variant-{index}")
        for index in range(4)
    ]
    plan = waf_pass_plan.validate_plan(plan, target="target.test")
    monkeypatch.setattr(probe, "PAYLOADS", [{
        "class": "sqli_auth_bypass",
        "value": "' OR 1=1--",
        "field_hint": ".*",
    }])
    responses = iter([
        {"status": 401, "body_text": '{"error":"bad"}', "body_size": 15, "headers": "", "latency": 0.05, "error": None},
        *[
            {"status": 403, "body_text": "Access Denied", "body_size": 12, "headers": "Server: cloudflare", "latency": 0.05, "error": None}
            for _ in range(5)
        ],
    ])
    calls = []

    def fake_post(url, body, timeout=10.0, **_kwargs):
        calls.append(body)
        return next(responses)

    monkeypatch.setattr(probe, "_http_post_json", fake_post)
    hits, events = probe.probe_endpoint(
        {"url": "https://target.test/login", "body_template": {"email": "a@b.test"}},
        max_requests=6,
        target="target.test",
        waf_plan=plan,
    )

    assert hits == []
    assert len(calls) == 6
    assert sum(event.get("variant_source") == "ai" for event in events) == 4


def test_json_probe_plan_request_budget_wins(tmp_path, monkeypatch):
    from tools import json_inject_probe as probe
    from tools import waf_pass_plan

    monkeypatch.setattr(waf_pass_plan, "BASE_DIR", tmp_path)
    artifact = _artifact(tmp_path)
    plan = _payload(artifact)
    plan["max_variants"] = 4
    plan["max_requests"] = 3
    plan["variants"] = [
        dict(plan["variants"][0], id=f"v-{index}", value=f"ai-variant-{index}")
        for index in range(4)
    ]
    plan = waf_pass_plan.validate_plan(plan, target="target.test")
    monkeypatch.setattr(probe, "PAYLOADS", [{
        "class": "sqli_auth_bypass",
        "value": "' OR 1=1--",
        "field_hint": ".*",
    }])
    responses = iter([
        {"status": 401, "body_text": '{"error":"bad"}', "body_size": 15, "headers": "", "latency": 0.05, "error": None},
        {"status": 403, "body_text": "Access Denied", "body_size": 12, "headers": "Server: cloudflare", "latency": 0.05, "error": None},
        {"status": 403, "body_text": "Access Denied", "body_size": 12, "headers": "Server: cloudflare", "latency": 0.05, "error": None},
    ])
    calls = []
    monkeypatch.setattr(probe, "_http_post_json", lambda url, body, timeout=10.0, **_kwargs: calls.append(body) or next(responses))

    probe.probe_endpoint(
        {"url": "https://target.test/login", "body_template": {"email": "a@b.test"}},
        max_requests=8,
        target="target.test",
        waf_plan=plan,
    )

    assert len(calls) == 3
