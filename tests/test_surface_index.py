"""完整 Surface exact index 的去重、变体和发布契约。"""

from __future__ import annotations

import json
import random

import pytest

from tools import surface_index as surface_index_module
from tools.surface_index import (
    SurfaceIndexError,
    SurfaceIndexRaceError,
    build_surface_index,
    iter_surface_index,
    load_surface_index_status,
    page_surface_index,
    surface_index_manifest_path,
)
from tools.surface import load_surface_context, rank_surface


def _write_inputs(repo_root):
    recon = repo_root / "recon" / "target.com"
    (recon / "urls").mkdir(parents=True)
    (recon / "live").mkdir()
    (recon / "browser").mkdir()
    (recon / "js").mkdir()
    base = "https://api.target.com/orders?id=1"
    variants = [
        "https://api.target.com/orders?id=2",
        "https://api.target.com/orders?id=1&id=2",
        "https://api.target.com/orders?id=2&id=1",
        "https://api.target.com/orders?a=1&b=2",
        "https://api.target.com/orders?b=2&a=1",
        "https://api.target.com/orders?q=a%2Fb",
        "https://api.target.com/orders?q=a+b",
        "http://api.target.com:8080/orders?id=1",
        "https://api.target.com/Orders?id=1",
        "https://api.target.com/orders/?id=1",
    ]
    (recon / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Python] [100]\n",
        encoding="utf-8",
    )
    (recon / "urls" / "api_endpoints.txt").write_text(base + "\n", encoding="utf-8")
    (recon / "urls" / "with_params.txt").write_text(
        "\n".join([base, *variants]) + "\n",
        encoding="utf-8",
    )
    (recon / "browser" / "xhr_endpoints.txt").write_text(base + "\n", encoding="utf-8")
    (recon / "browser" / "api_endpoints.txt").write_text("", encoding="utf-8")
    (recon / "js" / "endpoints.txt").write_text("/graphql\n", encoding="utf-8")

    findings = repo_root / "findings" / "target.com"
    findings.mkdir(parents=True)
    (findings / "findings.json").write_text(
        json.dumps({"schema_version": 1, "target": "target.com", "findings": [{"url": base}]}),
        encoding="utf-8",
    )
    return recon, base, variants


def test_exact_duplicates_merge_provenance_while_all_variants_remain(tmp_path):
    _recon, base, variants = _write_inputs(tmp_path)

    result = build_surface_index(tmp_path, "target.com")
    rows = list(iter_surface_index(tmp_path, "target.com"))
    by_url = {item["url"]: item for item in rows}

    assert result["summary"]["source_rows"] == len(variants) + 5
    assert result["summary"]["unique_urls"] == len(variants) + 2
    assert set(by_url) == {base, *variants, "https://api.target.com/graphql"}
    assert by_url[base]["sources"] == ["api", "param", "browser_xhr", "scanner"]
    assert by_url[base]["sequence"] == 0
    assert result["summary"]["exact_duplicates"] == 3
    assert result["summary"]["duplicate_key_urls"] == 2
    assert result["summary"]["encoded_query_urls"] == 2
    assert result["summary"]["non_default_port_urls"] == 1


def test_shape_groups_query_order_without_deleting_raw_identity(tmp_path):
    _write_inputs(tmp_path)
    build_surface_index(tmp_path, "target.com")
    rows = {item["url"]: item for item in iter_surface_index(tmp_path, "target.com")}

    left = rows["https://api.target.com/orders?a=1&b=2"]
    right = rows["https://api.target.com/orders?b=2&a=1"]
    assert left["shape_id"] == right["shape_id"]
    assert left["shape"]["ordered_parameter_names"] == ["a", "b"]
    assert right["shape"]["ordered_parameter_names"] == ["b", "a"]
    assert left["url"] != right["url"]


def test_input_change_marks_index_stale_without_consuming_rows(tmp_path):
    recon, _base, _variants = _write_inputs(tmp_path)
    build_surface_index(tmp_path, "target.com")
    assert load_surface_index_status(tmp_path, "target.com")["status"] == "valid"

    with (recon / "urls" / "with_params.txt").open("a", encoding="utf-8") as handle:
        handle.write("https://api.target.com/late?id=9\n")

    stale = load_surface_index_status(tmp_path, "target.com")
    assert stale["status"] == "stale"
    assert stale["reason"] == "input-manifest-mismatch"
    with pytest.raises(SurfaceIndexError, match="surface index unavailable"):
        list(iter_surface_index(tmp_path, "target.com"))


def test_sort_failure_cleans_staging_and_does_not_publish_manifest(tmp_path):
    _write_inputs(tmp_path)

    with pytest.raises(SurfaceIndexError, match="sort failed"):
        build_surface_index(
            tmp_path,
            "target.com",
            sort_executable="definitely-missing-surface-sort",
        )

    assert not surface_index_manifest_path(tmp_path, "target.com").exists()
    assert not list((tmp_path / "recon" / "target.com").glob(".surface-build.*"))


def test_input_race_refuses_publication(tmp_path, monkeypatch):
    _write_inputs(tmp_path)
    original = surface_index_module.build_surface_index_input_manifest
    calls = 0

    def racing_manifest(repo_root, target):
        nonlocal calls
        calls += 1
        payload = original(repo_root, target)
        if calls >= 2:
            payload = dict(payload)
            payload["fingerprint"] = "changed-during-build"
        return payload

    monkeypatch.setattr(surface_index_module, "build_surface_index_input_manifest", racing_manifest)

    with pytest.raises(SurfaceIndexRaceError, match="changed during build"):
        build_surface_index(tmp_path, "target.com")
    assert not surface_index_manifest_path(tmp_path, "target.com").exists()


def _rank_contract(payload):
    return {
        bucket: [
            {
                "url": item["url"],
                "score": item["score"],
                "score_breakdown": item.get("score_breakdown", []),
                "reasons": item.get("reasons", []),
                "review_reason": item.get("review_reason", ""),
            }
            for item in payload[bucket]
        ]
        for bucket in ("p1", "p2", "review_pool")
    }


def test_streaming_index_ranking_matches_legacy_rank_contract(tmp_path):
    _write_inputs(tmp_path)
    legacy = rank_surface(load_surface_context(tmp_path, "target.com"))

    build_surface_index(tmp_path, "target.com")
    indexed_context = load_surface_context(tmp_path, "target.com")
    assert indexed_context["surface_index"]["status"] == "valid"
    assert indexed_context["param_urls"] == []
    indexed = rank_surface(indexed_context)

    assert _rank_contract(indexed) == _rank_contract(legacy)
    assert indexed["stats"]["total_candidates"] == legacy["stats"]["total_candidates"]


def test_tail_candidate_survives_large_index_and_bounded_frontiers(tmp_path):
    recon, _base, _variants = _write_inputs(tmp_path)
    low_value = [f"https://api.target.com/archive/{index}" for index in range(5000)]
    tail = "https://api.target.com/admin/payments?account_id=999"
    (recon / "urls" / "with_params.txt").write_text(
        "\n".join([*low_value, tail]) + "\n",
        encoding="utf-8",
    )

    build_surface_index(tmp_path, "target.com")
    ranked = rank_surface(load_surface_context(tmp_path, "target.com"))

    assert tail in {item["url"] for item in ranked["p1"]}
    assert ranked["stats"]["total_candidates"] >= 5001
    assert len(ranked["p1"]) <= 8
    assert len(ranked["review_pool"]) <= 16


def test_probe_sanitization_does_not_duplicate_existing_exact_surface(tmp_path):
    recon = tmp_path / "recon" / "target.com"
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir()
    (recon / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Python] [100]\n",
        encoding="utf-8",
    )
    safe = "https://api.target.com/search?q=__probe__"
    probe = "https://api.target.com/search?q=<script>alert(1)</script>"
    (recon / "urls" / "with_params.txt").write_text(
        f"{safe}\n{probe}\n",
        encoding="utf-8",
    )

    legacy = rank_surface(load_surface_context(tmp_path, "target.com"))
    assert legacy["stats"]["total_candidates"] == 1

    build_surface_index(tmp_path, "target.com")
    indexed = rank_surface(load_surface_context(tmp_path, "target.com"))

    assert indexed["stats"]["total_candidates"] == 1
    assert _rank_contract(indexed) == _rank_contract(legacy)


def test_indexed_ranking_preserves_browser_js_source_convergence(tmp_path):
    recon = tmp_path / "recon" / "target.com"
    js_intel = tmp_path / "findings" / "target.com" / "js_intel"
    source_intel = tmp_path / "findings" / "target.com" / "source_intel"
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir()
    (recon / "js").mkdir()
    (recon / "browser").mkdir()
    js_intel.mkdir(parents=True)
    source_intel.mkdir(parents=True)
    url = "https://app.target.com/api/admin/export?order_id=42"
    (recon / "live" / "httpx_full.txt").write_text(
        "https://app.target.com [200] [App] [React] [1000]\n",
        encoding="utf-8",
    )
    (recon / "urls" / "api_endpoints.txt").write_text(url + "\n", encoding="utf-8")
    (recon / "urls" / "with_params.txt").write_text(url + "\n", encoding="utf-8")
    (recon / "js" / "endpoints.txt").write_text("", encoding="utf-8")
    (recon / "browser" / "xhr_endpoints.txt").write_text(url + "\n", encoding="utf-8")
    (recon / "browser" / "api_endpoints.txt").write_text(url + "\n", encoding="utf-8")
    (js_intel / "hypotheses.json").write_text(
        json.dumps(
            {
                "endpoints": [
                    {
                        "method": "POST",
                        "path": "/api/admin/export?order_id=42",
                        "source_file": "admin.js",
                    }
                ],
                "attack_surface_leads": [],
                "graphql_operations": [],
            }
        ),
        encoding="utf-8",
    )
    (source_intel / "routes.json").write_text(
        json.dumps({"routes": [{"route": "/api/admin/export?order_id=42"}]}),
        encoding="utf-8",
    )
    (source_intel / "hypotheses.jsonl").write_text(
        json.dumps(
            {
                "type": "idor",
                "candidate": "/api/admin/export?order_id=42",
                "reason": "order object boundary",
                "source": "routes/export.py",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    legacy = rank_surface(load_surface_context(tmp_path, "target.com"))
    build_surface_index(tmp_path, "target.com")
    indexed = rank_surface(load_surface_context(tmp_path, "target.com"))

    assert _rank_contract(indexed) == _rank_contract(legacy)
    assert indexed["workflow_leads"] == legacy["workflow_leads"]
    assert indexed["browser"] == legacy["browser"]
    assert indexed["stats"]["total_candidates"] == legacy["stats"]["total_candidates"]


def test_randomized_indexed_surface_matches_materialized_rank_contract(tmp_path):
    rng = random.Random(20260714)
    recon = tmp_path / "recon" / "target.com"
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir()
    (recon / "browser").mkdir()
    (recon / "js").mkdir()
    (recon / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [API] [Python,GraphQL] [100]\n",
        encoding="utf-8",
    )

    urls = []
    for index in range(400):
        host = "third.example" if index % 53 == 0 else "api.target.com"
        path = rng.choice(
            (
                f"/api/orders/{index % 37}",
                "/search",
                "/admin/export",
                "/graphql",
                "/ci/builds",
            )
        )
        pairs = [
            (rng.choice(("id", "order_id", "q", "redirect_uri")), str(index)),
            (rng.choice(("page", "sort", "q")), rng.choice(("1", "a%2Fb", "a+b"))),
        ]
        if index % 11 == 0:
            pairs.reverse()
        if index % 17 == 0:
            pairs.append((pairs[0][0], "duplicate"))
        query = "&".join(f"{key}={value}" for key, value in pairs)
        urls.append(f"https://{host}{path}?{query}")

    safe_probe = "https://api.target.com/search?q=__probe__"
    raw_probe = "https://api.target.com/search?q=<script>alert(1)</script>"
    urls.extend((safe_probe, raw_probe))
    api_urls = urls[::2] + urls[:15]
    param_urls = urls + urls[20:35]
    browser_xhr = urls[::7]
    browser_api = urls[::13]
    (recon / "urls" / "api_endpoints.txt").write_text(
        "\n".join(api_urls) + "\n",
        encoding="utf-8",
    )
    (recon / "urls" / "with_params.txt").write_text(
        "\n".join(param_urls) + "\n",
        encoding="utf-8",
    )
    (recon / "browser" / "xhr_endpoints.txt").write_text(
        "\n".join(browser_xhr) + "\n",
        encoding="utf-8",
    )
    (recon / "browser" / "api_endpoints.txt").write_text(
        "\n".join(browser_api) + "\n",
        encoding="utf-8",
    )
    (recon / "js" / "endpoints.txt").write_text(
        "/api/js-only?id=1\n/graphql\n",
        encoding="utf-8",
    )
    findings = tmp_path / "findings" / "target.com"
    findings.mkdir(parents=True)
    (findings / "findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target": "target.com",
                "findings": [
                    {
                        "id": f"candidate-{index}",
                        "type": "idor",
                        "url": url,
                        "validation_status": "unvalidated",
                        "report_status": "not_generated",
                    }
                    for index, url in enumerate(urls[::41])
                ],
            }
        ),
        encoding="utf-8",
    )

    legacy = rank_surface(load_surface_context(tmp_path, "target.com"))
    build_surface_index(tmp_path, "target.com")
    indexed = rank_surface(load_surface_context(tmp_path, "target.com"))

    assert _rank_contract(indexed) == _rank_contract(legacy)
    assert indexed["stats"]["total_candidates"] == legacy["stats"]["total_candidates"]
    assert indexed["workflow_leads"] == legacy["workflow_leads"]


def test_shape_cursor_pages_every_raw_variant_and_rejects_filter_change(tmp_path):
    _write_inputs(tmp_path)
    build_surface_index(tmp_path, "target.com")
    rows = list(iter_surface_index(tmp_path, "target.com"))
    shape_id = next(
        item["shape_id"]
        for item in rows
        if item["url"] == "https://api.target.com/orders?a=1&b=2"
    )
    expected = {item["url"] for item in rows if item["shape_id"] == shape_id}

    cursor = ""
    seen = []
    while True:
        page = page_surface_index(
            tmp_path,
            "target.com",
            shape_id=shape_id,
            limit=1,
            cursor=cursor,
        )
        seen.extend(item["url"] for item in page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert set(seen) == expected
    assert len(seen) == len(set(seen))

    first = page_surface_index(tmp_path, "target.com", limit=1)
    with pytest.raises(ValueError, match="filter mismatch"):
        page_surface_index(
            tmp_path,
            "target.com",
            limit=1,
            cursor=first["next_cursor"],
            source="api",
        )


def test_filtered_final_surface_page_does_not_emit_empty_follow_up_cursor(tmp_path):
    _write_inputs(tmp_path)
    build_surface_index(tmp_path, "target.com")

    page = page_surface_index(tmp_path, "target.com", source="scanner", limit=1)

    assert [item["url"] for item in page["items"]] == [
        "https://api.target.com/orders?id=1"
    ]
    assert page["next_cursor"] == ""
