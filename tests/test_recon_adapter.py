"""Tests for ReconAdapter — normalizes recon output across formats."""

import gzip
import json
import os
import pytest

from tools.recon_adapter import ReconAdapter, main as recon_adapter_main


def _ffuf_result(
    url,
    *,
    status=200,
    length=100,
    words=10,
    lines=2,
    content_type="text/html",
    fuzz="admin",
):
    return {
        "url": url,
        "status": status,
        "length": length,
        "words": words,
        "lines": lines,
        "content-type": content_type,
        "redirectlocation": "",
        "input": {"FUZZ": fuzz},
        "host": url.split("/", 3)[2],
    }


def _write_ffuf_jsonl(path, records, *, append=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "at" if append else "wt"
    opener = gzip.open if path.name.endswith(".gz") else open
    with opener(path, mode, encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


@pytest.fixture
def recon_dir(tmp_path):
    """Create a recon directory with the nested format from recon_engine.sh."""
    d = tmp_path / "recon" / "target.com"
    for sub in ("subdomains", "live", "ports", "urls", "js", "dirs", "params", "exposure"):
        (d / sub).mkdir(parents=True)
    return d


@pytest.fixture
def populated_recon(recon_dir):
    """Recon dir with sample data matching recon_engine.sh output."""
    (recon_dir / "subdomains" / "all.txt").write_text(
        "api.target.com\nwww.target.com\nstaging.target.com\n"
    )
    (recon_dir / "live" / "httpx_full.txt").write_text(
        "https://api.target.com [200] [application/json]\n"
        "https://www.target.com [200] [text/html]\n"
    )
    (recon_dir / "live" / "urls.txt").write_text(
        "https://api.target.com\nhttps://www.target.com\n"
    )
    (recon_dir / "urls" / "all.txt").write_text(
        "https://api.target.com/v1/users\n"
        "https://api.target.com/graphql\n"
        "https://www.target.com/login\n"
        "https://api.target.com/v1/users?id=1&role=admin\n"
    )
    (recon_dir / "urls" / "with_params.txt").write_text(
        "https://api.target.com/v1/users?id=1&role=admin\n"
    )
    (recon_dir / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.com/v1/users\nhttps://api.target.com/v1/orders\n"
    )
    (recon_dir / "urls" / "js_files.txt").write_text(
        "https://www.target.com/static/app.js\nhttps://www.target.com/static/vendor.js\n"
    )
    (recon_dir / "urls" / "sensitive_paths.txt").write_text(
        "https://www.target.com/.env\nhttps://api.target.com/.git/config\n"
    )
    (recon_dir / "js" / "potential_secrets.txt").write_text(
        "api.target.com/static/app.js: AWS_KEY=AKIA...\n"
    )
    (recon_dir / "params" / "interesting_params.txt").write_text(
        "redirect_url\ncallback\nnext\n"
    )
    (recon_dir / "exposure" / "config_files.txt").write_text(
        "https://www.target.com/.env [200]\n"
    )
    return recon_dir


# ── Reading data ──────────────────────────────────────────────────────────


class TestReconAdapterRead:
    """Reading recon data from nested directory format."""

    def test_get_subdomains(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        subs = adapter.get_subdomains()
        assert "api.target.com" in subs
        assert "www.target.com" in subs
        assert len(subs) == 3

    def test_get_live_hosts(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        hosts = adapter.get_live_hosts()
        assert "https://api.target.com" in hosts
        assert "https://www.target.com" in hosts

    def test_get_urls(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        urls = adapter.get_urls()
        assert len(urls) == 4
        assert "https://api.target.com/graphql" in urls

    def test_get_parameterized_urls(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        urls = adapter.get_parameterized_urls()
        assert len(urls) == 1
        assert "id=1" in urls[0]

    def test_get_js_files(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        js = adapter.get_js_files()
        assert len(js) == 2
        assert any("app.js" in f for f in js)

    def test_get_api_endpoints(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        apis = adapter.get_api_endpoints()
        assert len(apis) == 2

    def test_get_sensitive_paths(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        paths = adapter.get_sensitive_paths()
        assert len(paths) == 2
        assert any(".env" in p for p in paths)

    def test_get_js_secrets(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        secrets = adapter.get_js_secrets()
        assert len(secrets) == 1
        assert "AWS_KEY" in secrets[0]

    def test_get_interesting_params(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        params = adapter.get_interesting_params()
        assert "redirect_url" in params
        assert "callback" in params

    def test_get_config_exposure(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        exposed = adapter.get_config_exposure()
        assert len(exposed) == 1
        assert ".env" in exposed[0]


# ── GraphQL extraction ───────────────────────────────────────────────────


class TestReconAdapterGraphQL:
    """Extracting GraphQL endpoints from URL lists."""

    def test_get_graphql_endpoints_from_urls(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        gql = adapter.get_graphql_endpoints()
        assert len(gql) == 1
        assert "graphql" in gql[0]

    def test_get_graphql_from_dedicated_file(self, populated_recon):
        """If urls/graphql.txt exists, prefer it."""
        (populated_recon / "urls" / "graphql.txt").write_text(
            "https://api.target.com/graphql\nhttps://api.target.com/gql\n"
        )
        adapter = ReconAdapter(populated_recon)
        gql = adapter.get_graphql_endpoints()
        assert len(gql) == 2

    def test_get_graphql_empty_when_none(self, recon_dir):
        (recon_dir / "urls" / "all.txt").write_text("https://target.com/login\n")
        adapter = ReconAdapter(recon_dir)
        gql = adapter.get_graphql_endpoints()
        assert gql == []


# ── Fallback path resolution ─────────────────────────────────────────────


class TestReconAdapterFallbacks:
    """Fallback paths for agent.py compatibility."""

    def test_live_hosts_fallback_to_root_httpx(self, recon_dir):
        """If live/httpx_full.txt missing but httpx_full.txt at root, use that."""
        (recon_dir / "httpx_full.txt").write_text(
            "https://api.target.com [200] [json]\n"
        )
        adapter = ReconAdapter(recon_dir)
        hosts = adapter.get_live_hosts()
        assert len(hosts) == 1

    def test_returns_empty_for_missing_files(self, recon_dir):
        """Missing files return empty lists, not errors."""
        adapter = ReconAdapter(recon_dir)
        assert adapter.get_subdomains() == []
        assert adapter.get_live_hosts() == []
        assert adapter.get_urls() == []
        assert adapter.get_parameterized_urls() == []

    def test_resolved_subdomains_fallback(self, recon_dir):
        """get_resolved_subdomains tries resolved.txt then falls back to all.txt."""
        (recon_dir / "subdomains" / "all.txt").write_text("a.target.com\nb.target.com\n")
        adapter = ReconAdapter(recon_dir)
        resolved = adapter.get_resolved_subdomains()
        assert len(resolved) == 2

    def test_resolved_subdomains_prefers_resolved_file(self, recon_dir):
        (recon_dir / "subdomains" / "resolved.txt").write_text("a.target.com\n")
        (recon_dir / "subdomains" / "all.txt").write_text("a.target.com\nb.target.com\n")
        adapter = ReconAdapter(recon_dir)
        resolved = adapter.get_resolved_subdomains()
        assert len(resolved) == 1


# ── Normalize (create missing stubs) ─────────────────────────────────────


class TestReconAdapterNormalize:
    """normalize() ensures all expected files exist for brain.py."""

    def test_normalize_creates_priority_dir(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        assert (populated_recon / "priority").is_dir()

    def test_normalize_creates_graphql_file(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        gql_file = populated_recon / "urls" / "graphql.txt"
        assert gql_file.exists()
        content = gql_file.read_text()
        assert "graphql" in content

    def test_normalize_creates_resolved_txt(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        resolved = populated_recon / "subdomains" / "resolved.txt"
        assert resolved.exists()

    def test_normalize_creates_prioritized_hosts_json(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        pj = populated_recon / "priority" / "prioritized_hosts.json"
        assert pj.exists()
        data = json.loads(pj.read_text())
        assert isinstance(data, dict)
        assert "hosts" in data

    def test_normalize_creates_attack_surface_md(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        md = populated_recon / "priority" / "attack_surface.md"
        assert md.exists()
        assert "target.com" in md.read_text().lower() or "Attack Surface" in md.read_text()

    def test_normalize_does_not_overwrite_existing(self, populated_recon):
        """Existing files are preserved, not overwritten."""
        (populated_recon / "urls" / "graphql.txt").write_text("https://custom.com/gql\n")
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        content = (populated_recon / "urls" / "graphql.txt").read_text()
        assert "custom.com" in content

    def test_normalize_creates_api_specs_dir(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        assert (populated_recon / "api_specs").is_dir()

    def test_normalize_idempotent(self, populated_recon):
        """Running normalize twice doesn't break anything."""
        adapter = ReconAdapter(populated_recon)
        adapter.normalize()
        adapter.normalize()
        assert (populated_recon / "priority" / "prioritized_hosts.json").exists()


# ── Summary ──────────────────────────────────────────────────────────────


class TestReconAdapterSummary:
    """summary() returns a quick overview dict."""

    def test_summary_counts(self, populated_recon):
        adapter = ReconAdapter(populated_recon)
        s = adapter.summary()
        assert s["subdomains"] == 3
        assert s["live_hosts"] == 2
        assert s["urls"] == 4
        assert s["parameterized_urls"] == 1
        assert s["js_files"] == 2
        assert s["api_endpoints"] == 2

    def test_summary_empty_recon(self, recon_dir):
        adapter = ReconAdapter(recon_dir)
        s = adapter.summary()
        assert s["subdomains"] == 0
        assert s["live_hosts"] == 0


# ── Edge cases ───────────────────────────────────────────────────────────


class TestReconAdapterEdgeCases:
    """Edge cases and error handling."""

    def test_nonexistent_recon_dir(self, tmp_path):
        adapter = ReconAdapter(tmp_path / "nonexistent")
        assert adapter.get_subdomains() == []
        assert adapter.get_urls() == []

    def test_empty_files(self, recon_dir):
        (recon_dir / "subdomains" / "all.txt").write_text("")
        adapter = ReconAdapter(recon_dir)
        assert adapter.get_subdomains() == []

    def test_files_with_blank_lines(self, recon_dir):
        (recon_dir / "subdomains" / "all.txt").write_text("\n\na.target.com\n\n\nb.target.com\n\n")
        adapter = ReconAdapter(recon_dir)
        subs = adapter.get_subdomains()
        assert len(subs) == 2

    def test_duplicate_entries_deduplicated(self, recon_dir):
        (recon_dir / "subdomains" / "all.txt").write_text("a.target.com\na.target.com\nb.target.com\n")
        adapter = ReconAdapter(recon_dir)
        subs = adapter.get_subdomains()
        assert len(subs) == 2


class TestReconAdapterFfuf:
    """FFUF artifacts stay lossless on disk and bounded in AI-facing views."""

    def test_summary_streams_gzip_and_ignores_sensitive_fields(self, recon_dir, tmp_path):
        artifact = recon_dir / "dirs" / "ffuf_results.jsonl.gz"
        records = [
            {
                **_ffuf_result(
                    f"https://target.com/path-{index}",
                    status=403,
                    length=123,
                    fuzz=f"path-{index}",
                ),
                "headers": {"Authorization": "Bearer SHOULD_NOT_LEAK"},
                "cookie": "session=SHOULD_NOT_LEAK",
            }
            for index in range(20)
        ]
        records.append(_ffuf_result("https://target.com/real", status=200, length=456))
        _write_ffuf_jsonl(artifact, records)

        controls = tmp_path / "controls.jsonl"
        _write_ffuf_jsonl(
            controls,
            [_ffuf_result("https://target.com/__missing", status=403, length=123)],
        )
        adapter = ReconAdapter(recon_dir)
        summary = adapter.summarize_ffuf_results(
            attempted=1,
            succeeded=1,
            control_failed=1,
            controls_path=controls,
        )

        assert summary["observations"] == 21
        assert summary["status_counts"] == {"200": 1, "403": 20}
        assert summary["control_failed"] == 1
        assert summary["heavy_signatures"][0]["count"] == 20
        assert summary["heavy_signatures"][0]["matches_random_miss_control"] is True
        assert summary["sample_count"] == 2
        summary_text = json.dumps(summary)
        assert "SHOULD_NOT_LEAK" not in summary_text
        assert adapter.get_ffuf_summary()["available"] is True

    def test_reads_concatenated_gzip_members(self, recon_dir):
        artifact = recon_dir / "dirs" / "ffuf_results.jsonl.gz"
        _write_ffuf_jsonl(artifact, [_ffuf_result("https://target.com/a")])
        _write_ffuf_jsonl(
            artifact,
            [_ffuf_result("https://target.com/b", status=405)],
            append=True,
        )

        observations = list(ReconAdapter(recon_dir).iter_ffuf_observations())

        assert [item["url"] for item in observations] == [
            "https://target.com/a",
            "https://target.com/b",
        ]

    def test_control_filter_size_requires_two_matching_200_responses(self, recon_dir, tmp_path):
        controls = tmp_path / "controls.jsonl"
        _write_ffuf_jsonl(
            controls,
            [
                _ffuf_result("https://target.com/missing-a", status=200, length=321),
                _ffuf_result("https://target.com/missing-b", status=200, length=321),
            ],
        )
        adapter = ReconAdapter(recon_dir)
        assert adapter.get_ffuf_control_filter_size(controls) == 321

        _write_ffuf_jsonl(
            controls,
            [
                _ffuf_result("https://target.com/missing-a", status=403, length=321),
                _ffuf_result("https://target.com/missing-b", status=403, length=321),
            ],
        )
        assert adapter.get_ffuf_control_filter_size(controls) == 0

    def test_malformed_json_is_partial_evidence_not_total_failure(self, recon_dir):
        artifact = recon_dir / "dirs" / "ffuf_results.jsonl"
        artifact.write_text(
            json.dumps(_ffuf_result("https://target.com/a"))
            + "\n{broken\n"
            + json.dumps(_ffuf_result("https://target.com/b", status=403))
            + "\n",
            encoding="utf-8",
        )

        summary = ReconAdapter(recon_dir).summarize_ffuf_results()

        assert summary["observations"] == 2
        assert summary["parse_error_count"] == 1
        assert len(summary["parse_error_preview"]) == 1

    def test_heavy_signatures_use_bounded_output(self, recon_dir):
        artifact = recon_dir / "dirs" / "ffuf_results.jsonl.gz"
        records = [
            _ffuf_result(
                f"https://target.com/noise-{index}",
                status=403,
                length=1000 + index,
            )
            for index in range(100)
        ]
        records.extend(
            _ffuf_result(
                f"https://target.com/dominant-{index}",
                status=403,
                length=777,
            )
            for index in range(100)
        )
        _write_ffuf_jsonl(artifact, records)

        summary = ReconAdapter(recon_dir).summarize_ffuf_results()

        assert len(summary["heavy_signatures"]) <= 8
        dominant = next(item for item in summary["heavy_signatures"] if item["length"] == 777)
        assert dominant["count"] == 100
        assert dominant["ratio"] == 0.5

    def test_bounded_page_filters_by_status_and_signature(self, recon_dir):
        artifact = recon_dir / "dirs" / "ffuf_results.jsonl"
        _write_ffuf_jsonl(
            artifact,
            [
                _ffuf_result("https://target.com/a", status=403, length=123),
                _ffuf_result("https://target.com/b", status=200, length=456),
                _ffuf_result("https://target.com/c", status=403, length=123),
            ],
        )
        adapter = ReconAdapter(recon_dir)
        summary = adapter.summarize_ffuf_results()
        signature_id = next(
            item["signature_id"]
            for item in summary["heavy_signatures"]
            if item["status"] == 403
        )

        status_page = adapter.get_ffuf_observations(status=403, offset=1, limit=1)
        signature_page = adapter.get_ffuf_observations(signature_id=signature_id, limit=10)

        assert [item["url"] for item in status_page] == ["https://target.com/c"]
        assert len(signature_page) == 2
        with pytest.raises(ValueError):
            adapter.get_ffuf_observations(limit=1001)

    def test_stale_summary_is_not_consumed(self, recon_dir):
        artifact = recon_dir / "dirs" / "ffuf_results.jsonl"
        _write_ffuf_jsonl(artifact, [_ffuf_result("https://target.com/a")])
        adapter = ReconAdapter(recon_dir)
        adapter.summarize_ffuf_results()
        stat = artifact.stat()
        os.utime(artifact, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1))

        summary = adapter.get_ffuf_summary()

        assert summary["available"] is False
        assert summary["stale"] is True
        assert summary["needs_summary"] is True

    def test_legacy_raw_is_only_read_explicitly(self, recon_dir):
        legacy = recon_dir / "dirs" / "ffuf_target.com.json"
        legacy.write_text(
            json.dumps({
                "config": {"headers": {"Authorization": "Bearer SECRET"}},
                "results": [_ffuf_result("https://target.com/legacy", status=301)],
            }),
            encoding="utf-8",
        )
        adapter = ReconAdapter(recon_dir)

        unavailable = adapter.get_ffuf_summary()
        assert unavailable["needs_summary"] is True
        assert unavailable["legacy_raw_files"] == 1
        assert list(adapter.iter_ffuf_observations()) == []
        assert len(list(adapter.iter_ffuf_observations(include_legacy=True))) == 1

        summary = adapter.summarize_ffuf_results(include_legacy=True)
        assert summary["observations"] == 1
        assert "SECRET" not in json.dumps(summary)

    def test_cli_summarizes_and_reads_bounded_pages(self, recon_dir, capsys):
        artifact = recon_dir / "dirs" / "ffuf_results.jsonl"
        _write_ffuf_jsonl(
            artifact,
            [
                _ffuf_result("https://target.com/a", status=403),
                _ffuf_result("https://target.com/b", status=200),
            ],
        )

        assert recon_adapter_main([
            "--recon-dir", str(recon_dir),
            "--summarize-ffuf",
            "--attempted", "1",
            "--succeeded", "1",
        ]) == 0
        summary = json.loads(capsys.readouterr().out)
        assert summary["observations"] == 2

        assert recon_adapter_main([
            "--recon-dir", str(recon_dir),
            "--read-ffuf",
            "--status", "403",
            "--limit", "1",
        ]) == 0
        page = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
        assert [item["url"] for item in page] == ["https://target.com/a"]
