import json

from tools.recon_candidates import build_js_deep_candidates, build_recon_candidates
from tools.runtime_state import inspect_recon_artifacts
from tools.surface import _build_exposure_lead_hints


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
