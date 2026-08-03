import json

import pytest

from memory.target_profile import make_target_profile, save_target_profile
from tools.recon_candidates import (
    _normalize_asset_relation_observation,
    build_js_deep_candidates,
    build_recon_candidates,
)
from tools.runtime_state import inspect_recon_artifacts, inspect_recon_artifacts_fast
from tools.surface import _build_exposure_lead_hints
from tools.target_paths import target_storage_key


def _empty_recon(tmp_path, target):
    recon = tmp_path / "recon" / target_storage_key(target)
    for relative in ("live", "urls", "exposure", "js", "browser"):
        (recon / relative).mkdir(parents=True, exist_ok=True)
    (recon / "live" / "httpx_full.txt").write_text("", encoding="utf-8")
    return recon


def test_build_recon_candidates_uses_existing_evidence_only(tmp_path):
    recon = tmp_path / "recon" / "target.com"
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir()
    (recon / "exposure").mkdir()
    (recon / "js").mkdir()
    (recon / "browser").mkdir()
    (recon / "live" / "httpx_full.txt").write_text(
        "https://chat.target.com [200] [AI Console] [ip=192.0.2.10] [cname=edge.target.com]\n"
        "https://api.target.com [200] [API] [ip=192.0.2.10]\n",
        encoding="utf-8",
    )
    (recon / "live" / "origin_candidates.txt").write_text("192.0.2.20\n", encoding="utf-8")
    (recon / "live" / "unwaf_bypass_ips.txt").write_text("", encoding="utf-8")
    (recon / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/v1/embeddings\n",
        encoding="utf-8",
    )
    (recon / "urls" / "js_files.txt").write_text(
        "https://static.target.com/openai-client.js\n",
        encoding="utf-8",
    )
    (recon / "exposure" / "api_doc_candidates.txt").write_text("", encoding="utf-8")
    (recon / "js" / "endpoints.txt").write_text("/agent/tools\n", encoding="utf-8")

    result = build_recon_candidates(tmp_path, "target.com")
    host_rows = [
        json.loads(line)
        for line in (recon / "exposure" / "host_pivot_candidates.jsonl").read_text().splitlines()
    ]
    ai_rows = [
        json.loads(line)
        for line in (recon / "exposure" / "ai_asset_candidates.jsonl").read_text().splitlines()
    ]

    assert result["host_pivot_candidates"] >= 3
    assert result["asset_relation_candidates"] == 0
    assert any(row["signals"] == ["shared-ip"] for row in host_rows)
    assert any("cname" in row["signals"] for row in host_rows)
    assert {row["value"] for row in ai_rows} >= {
        "https://chat.target.com [200] [AI Console] [ip=192.0.2.10] [cname=edge.target.com]",
        "https://api.target.com/v1/embeddings",
        "https://static.target.com/openai-client.js",
        "/agent/tools",
    }

    artifacts = inspect_recon_artifacts(tmp_path, "target.com")
    categories = {
        item["category"]
        for item in _build_exposure_lead_hints(artifacts, "target.com")
    }
    assert artifacts["counts"]["host_pivot_candidates"] == len(host_rows)
    assert artifacts["counts"]["ai_asset_candidates"] == len(ai_rows)
    assert {"host-pivot", "ai-asset"}.issubset(categories)


def test_asset_relation_observations_merge_provenance_into_one_soft_lead(tmp_path):
    recon = tmp_path / "recon" / "target.com"
    for relative in ("live", "urls", "exposure", "js", "browser"):
        (recon / relative).mkdir(parents=True, exist_ok=True)
    (recon / "live" / "httpx_full.txt").write_text("", encoding="utf-8")
    observations = [
        {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": "domain",
            "value": "edge.target.net",
            "relation": "certificate-san",
            "related": ["target.com", "api.target.com"],
            "signals": ["shared-certificate"],
            "source": "certificate-transparency",
            "source_ref": "ct-log:SERIAL",
            "confidence": "medium",
            "observed_at": "2026-07-20T10:00:00+00:00",
        },
        {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": "DOMAIN",
            "value": "edge.target.net",
            "relation": "CERTIFICATE-SAN",
            "related": ["admin.target.com", "target.com"],
            "signals": ["historical-resolution"],
            "source": "passive-dns",
            "source_ref": "pdns:SERIAL",
            "confidence": "high",
            "observed_at": "2026-07-21T11:00:00Z",
        },
    ]
    input_path = recon / "exposure" / "asset_relation_observations.jsonl"
    input_path.write_text(
        "\n".join(json.dumps(item) for item in observations)
        + "\n{not-json}\n"
        + json.dumps({"schema_version": 1, "kind": "asset-relation-observation"})
        + "\n",
        encoding="utf-8",
    )

    result = build_recon_candidates(tmp_path, "target.com")
    rows = [
        json.loads(line)
        for line in (recon / "exposure" / "asset_relation_candidates.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]

    assert result["asset_relation_observations"] == 4
    assert result["asset_relation_invalid"] == 2
    assert len(result["asset_relation_warnings"]) == 2
    assert result["asset_relation_candidates"] == 1
    assert rows == [
        {
            "schema_version": 1,
            "kind": "asset-relation-candidate",
            "asset_type": "domain",
            "value": "edge.target.net",
            "relation": "certificate-san",
            "related": ["admin.target.com", "api.target.com", "target.com"],
            "signals": ["historical-resolution", "shared-certificate"],
            "sources": ["certificate-transparency", "passive-dns"],
            "source_refs": ["ct-log:SERIAL", "pdns:SERIAL"],
            "confidence": "high",
            "observed_at": "2026-07-21T11:00:00Z",
            "scope_status": "scope-review",
            "scope_reason": "high-confidence target-linked certificate-san relationship",
        }
    ]
    summary = json.loads(
        (recon / "exposure" / "asset_relation_summary.json").read_text(encoding="utf-8")
    )
    assert summary["status_counts"] == {"scope-review": 1}
    assert summary["scope_review_pending"] == 1
    assert summary["candidate_bytes"] == (
        recon / "exposure" / "asset_relation_candidates.jsonl"
    ).stat().st_size

    artifacts = inspect_recon_artifacts(tmp_path, "target.com")
    leads = _build_exposure_lead_hints(artifacts, "target.com")
    asset_lead = next(item for item in leads if item["category"] == "asset-scope-review")
    assert artifacts["counts"]["asset_relation_candidates"] == 1
    assert artifacts["exposure_paths"]["asset_relation_candidates"] == (
        "exposure/asset_relation_candidates.jsonl"
    )
    assert artifacts["asset_relations"]["scope_review_pending"] == 1
    assert asset_lead["source"] == "recon_routing_candidate"
    assert asset_lead["priority"] == "high"
    assert "Scope" in asset_lead["next_action"]
    assert "do not issue active requests" in asset_lead["next_action"]
    fast_artifacts = inspect_recon_artifacts_fast(tmp_path, "target.com")
    assert fast_artifacts["counts"]["asset_relation_candidates"] is None
    assert fast_artifacts["asset_relations"]["scope_review_pending"] == 1


def test_asset_relation_candidates_are_bounded_and_prioritized(tmp_path):
    recon = tmp_path / "recon" / "target.com"
    for relative in ("live", "urls", "exposure", "js", "browser"):
        (recon / relative).mkdir(parents=True, exist_ok=True)
    (recon / "live" / "httpx_full.txt").write_text("", encoding="utf-8")

    def observation(value, *, confidence="low", source="registry", signal="whois"):
        return {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": "domain",
            "value": value,
            "relation": "shared-owner",
            "signals": [signal],
            "source": source,
            "confidence": confidence,
        }

    records = [
        observation("low.example"),
        observation("high-single.example", confidence="high", source="ct", signal="san"),
        observation("high-multi.example", confidence="high", source="ct", signal="san"),
        observation("high-multi.example", confidence="high", source="pdns", signal="history"),
    ]
    input_path = recon / "exposure" / "asset_relation_observations.jsonl"
    input_path.write_bytes(
        ("x" * 1_000_001 + "\n").encode()
        + "".join(json.dumps(item) + "\n" for item in records).encode()
    )
    original = input_path.read_bytes()

    result = build_recon_candidates(tmp_path, "target.com", asset_limit=2)
    rows = [
        json.loads(line)
        for line in (recon / "exposure" / "asset_relation_candidates.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]

    assert input_path.read_bytes() == original
    assert result["asset_relation_observations"] == 5
    assert result["asset_relation_invalid"] == 1
    assert result["asset_relation_unique"] == 3
    assert result["asset_relation_candidates"] == 2
    assert result["asset_relation_truncated"] is True
    assert [row["value"] for row in rows] == [
        "high-multi.example",
        "high-single.example",
    ]
    assert rows[0]["sources"] == ["ct", "pdns"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ownership_pct", -1),
        ("ownership_pct", 101),
        ("ownership_pct", True),
        ("depth", -1),
        ("depth", 5),
        ("depth", 1.5),
        ("entity_ref", "x" * 4097),
    ],
)
def test_asset_relation_recursion_metadata_rejects_invalid_values(field, value):
    payload = {
        "schema_version": 1,
        "kind": "asset-relation-observation",
        "asset_type": "organization",
        "value": "Target Holdings",
        "relation": "majority-owned",
        "source": "registry",
        field: value,
    }

    with pytest.raises(ValueError):
        _normalize_asset_relation_observation(payload)


def test_asset_relation_metadata_merges_without_changing_raw_observations(tmp_path):
    recon = _empty_recon(tmp_path, "target.com")
    observations = [
        {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": "organization",
            "value": "Controlled Company",
            "relation": "majority-owned",
            "related": ["target.com"],
            "source": "lei",
            "confidence": "high",
            "entity_ref": "lei:child",
            "parent_ref": "lei:parent-a",
            "ownership_pct": 51.5,
            "depth": 2,
        },
        {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": "organization",
            "value": "Controlled Company",
            "relation": "majority-owned",
            "related": ["target.com"],
            "source": "registry",
            "confidence": "high",
            "entity_ref": "registry:child",
            "parent_ref": "registry:parent-b",
            "ownership_pct": 75,
            "depth": 1,
        },
    ]
    input_path = recon / "exposure" / "asset_relation_observations.jsonl"
    input_path.write_text(
        "".join(json.dumps(row) + "\n" for row in observations),
        encoding="utf-8",
    )
    original = input_path.read_bytes()

    build_recon_candidates(tmp_path, "target.com")
    row = json.loads(
        (recon / "exposure" / "asset_relation_candidates.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )

    assert input_path.read_bytes() == original
    assert row["entity_refs"] == ["lei:child", "registry:child"]
    assert row["parent_refs"] == ["lei:parent-a", "registry:parent-b"]
    assert row["ownership_pct"] == 75.0
    assert row["depth"] == 1
    assert row["scope_status"] == "scope-review"


def test_asset_relation_scope_keeps_target_link_when_related_view_is_truncated(tmp_path):
    recon = _empty_recon(tmp_path, "target.com")
    observations = [
        {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": "domain",
            "value": "edge.external.example",
            "relation": "certificate-san",
            "related": [f"a{index:03}.example"],
            "source": "ct",
            "confidence": "high",
        }
        for index in range(256)
    ] + [
        {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": "domain",
            "value": "edge.external.example",
            "relation": "certificate-san",
            "related": ["target.com"],
            "source": "ct",
            "confidence": "high",
        }
    ]
    (recon / "exposure" / "asset_relation_observations.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in observations),
        encoding="utf-8",
    )

    build_recon_candidates(tmp_path, "target.com")
    row = json.loads(
        (recon / "exposure" / "asset_relation_candidates.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )

    assert len(row["related"]) == 256
    assert "target.com" not in row["related"]
    assert row["scope_status"] == "scope-review"


def test_asset_relation_scope_dispositions_keep_external_context(tmp_path):
    recon = _empty_recon(tmp_path, "target.com")
    profile = make_target_profile(
        "target.com",
        scope_snapshot={
            "in_scope": ["target.com", "10.0.0.0/8"],
            "out_of_scope": ["excluded.target.com", "10.9.0.0/16"],
        },
    )
    save_target_profile(tmp_path / "hunt-memory", profile)
    rows = [
        ("domain", "api.target.com", "service", [], "medium", "registry"),
        ("domain", "excluded.target.com", "service", ["target.com"], "high", "registry"),
        ("ip", "10.9.1.2", "origin", ["target.com"], "high", "pdns"),
        ("url", "https://edge.external.example/app", "certificate-san", ["target.com"], "high", "ct"),
        ("domain", "supplier.example", "supplier", ["target.com"], "medium", "registry"),
        ("domain", "excluded-linked.example", "certificate-san", ["excluded.target.com"], "high", "ct"),
        ("asn", "AS64500", "network-owner", [], "medium", "bgp"),
        ("domain", "/relative", "embedded-link", ["target.com"], "high", "html"),
    ]
    observations = [
        {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": asset_type,
            "value": value,
            "relation": relation,
            "related": related,
            "source": source,
            "confidence": confidence,
        }
        for asset_type, value, relation, related, confidence, source in rows
    ]
    (recon / "exposure" / "asset_relation_observations.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in observations),
        encoding="utf-8",
    )

    build_recon_candidates(tmp_path, "target.com")
    candidates = {
        row["value"]: row
        for row in map(
            json.loads,
            (recon / "exposure" / "asset_relation_candidates.jsonl")
            .read_text(encoding="utf-8")
            .splitlines(),
        )
    }

    assert candidates["api.target.com"]["scope_status"] == "in_scope"
    assert candidates["excluded.target.com"]["scope_status"] == "excluded"
    assert candidates["10.9.1.2"]["scope_status"] == "excluded"
    assert candidates["https://edge.external.example/app"]["scope_status"] == "scope-review"
    assert candidates["supplier.example"]["scope_status"] == "external-chain-context"
    assert candidates["excluded-linked.example"]["scope_status"] == "external-chain-context"
    assert candidates["AS64500"]["scope_status"] == "unknown"
    assert candidates["/relative"]["scope_status"] == "unknown"


def test_asset_relation_summary_target_mismatch_is_not_used_by_fast_bootstrap(tmp_path):
    recon = _empty_recon(tmp_path, "target.com")
    (recon / "exposure" / "asset_relation_summary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "asset-relation-summary",
                "target": "other.example",
                "status_counts": {"scope-review": 1},
                "scope_review_pending": 1,
            }
        ),
        encoding="utf-8",
    )

    artifacts = inspect_recon_artifacts_fast(tmp_path, "target.com")

    assert artifacts["asset_relations"]["available"] is False
    assert "target mismatch" in artifacts["asset_relations"]["error"]
    assert any("asset relation summary is invalid" in warning for warning in artifacts["warnings"])


def test_asset_relation_summary_candidate_mismatch_is_not_used_by_fast_bootstrap(tmp_path):
    recon = _empty_recon(tmp_path, "target.com")
    (recon / "exposure" / "asset_relation_candidates.jsonl").write_text(
        "{}\n", encoding="utf-8"
    )
    (recon / "exposure" / "asset_relation_summary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "asset-relation-summary",
                "target": "target.com",
                "candidate_bytes": 0,
                "status_counts": {"scope-review": 1},
                "scope_review_pending": 1,
            }
        ),
        encoding="utf-8",
    )

    artifacts = inspect_recon_artifacts_fast(tmp_path, "target.com")

    assert artifacts["asset_relations"]["available"] is False
    assert "candidate projection mismatch" in artifacts["asset_relations"]["error"]


def test_asset_relation_summary_scope_count_mismatch_is_not_used_by_fast_bootstrap(tmp_path):
    recon = _empty_recon(tmp_path, "target.com")
    candidate_path = recon / "exposure" / "asset_relation_candidates.jsonl"
    candidate_path.write_text("{}\n", encoding="utf-8")
    (recon / "exposure" / "asset_relation_summary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "asset-relation-summary",
                "target": "target.com",
                "candidate_bytes": candidate_path.stat().st_size,
                "status_counts": {"scope-review": 0},
                "scope_review_pending": 1,
            }
        ),
        encoding="utf-8",
    )

    artifacts = inspect_recon_artifacts_fast(tmp_path, "target.com")

    assert artifacts["asset_relations"]["available"] is False
    assert "scope review count mismatch" in artifacts["asset_relations"]["error"]


@pytest.mark.parametrize(
    ("target", "asset_type", "value"),
    [
        ("192.0.2.10", "ip", "192.0.2.10"),
        ("192.0.2.0/24", "ip", "192.0.2.42"),
    ],
)
def test_asset_relation_scope_supports_ip_and_cidr_targets(tmp_path, target, asset_type, value):
    recon = _empty_recon(tmp_path, target)
    observation = {
        "schema_version": 1,
        "kind": "asset-relation-observation",
        "asset_type": asset_type,
        "value": value,
        "relation": "direct-target",
        "source": "operator",
        "confidence": "high",
    }
    (recon / "exposure" / "asset_relation_observations.jsonl").write_text(
        json.dumps(observation) + "\n",
        encoding="utf-8",
    )

    build_recon_candidates(tmp_path, target)
    row = json.loads(
        (recon / "exposure" / "asset_relation_candidates.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    assert row["scope_status"] == "in_scope"


def test_asset_relation_scope_supports_target_lists(tmp_path):
    target_list = tmp_path / "targets.txt"
    target_list.write_text("*.listed.example\n192.0.2.0/24\n", encoding="utf-8")
    recon = _empty_recon(tmp_path, str(target_list))
    observations = [
        {
            "schema_version": 1,
            "kind": "asset-relation-observation",
            "asset_type": asset_type,
            "value": value,
            "relation": "direct-target",
            "source": "operator",
            "confidence": "high",
        }
        for asset_type, value in (("domain", "api.listed.example"), ("ip", "192.0.2.42"))
    ]
    (recon / "exposure" / "asset_relation_observations.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in observations),
        encoding="utf-8",
    )

    build_recon_candidates(tmp_path, str(target_list))
    rows = [
        json.loads(line)
        for line in (recon / "exposure" / "asset_relation_candidates.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert {row["scope_status"] for row in rows} == {"in_scope"}


def test_js_deep_candidates_are_bounded_and_keep_category_representatives(tmp_path):
    source = tmp_path / "js_files_analysis.txt"
    output = tmp_path / "deep_candidates.txt"
    categories = {
        "auth": "https://cdn.target.com/auth-{index}.js",
        "api": "https://cdn.target.com/api-{index}.js",
        "payment": "https://cdn.target.com/payment-{index}.js",
        "file": "https://cdn.target.com/upload-{index}.js",
        "source-map": "https://cdn.target.com/app-{index}.js.map",
        "dynamic": "https://cdn.target.com/signature-{index}.js",
        "framework": "https://cdn.target.com/chunk-{index}.js",
        "general": "https://cdn.target.com/static-{index}.js",
    }
    source.write_text(
        "".join(
            template.format(index=index) + "\n"
            for template in categories.values()
            for index in range(20)
        ),
        encoding="utf-8",
    )

    result = build_js_deep_candidates(source, output, limit=16)
    candidates = output.read_text(encoding="utf-8").splitlines()

    assert result["input_count"] == 160
    assert result["candidate_count"] <= 16
    assert result["truncated"] is True
    expected_markers = (
        "auth-",
        "api-",
        "payment-",
        "upload-",
        ".js.map",
        "signature-",
        "chunk-",
        "static-",
    )
    assert all(any(marker in value for value in candidates) for marker in expected_markers)
