import json
from pathlib import Path

import pytest

from tools import recon_filters


def test_filter_external_urls_keeps_target_subdomains_ports_cdn_and_relative_paths():
    urls = [
        "https://example.com/",
        "https://api.example.com:8443/v1",
        "api.example.com:8443/v1",
        "https://cdn.example.com/app.js",
        "/api/internal",
        "//api.example.com/protocol-relative",
        "//evil.com/protocol-relative",
        "javascript:alert(1)",
        "https://evil-example.com/",
        "https://thirdparty.test/callback",
    ]

    assert recon_filters.filter_external_urls(urls, "example.com") == [
        "https://example.com/",
        "https://api.example.com:8443/v1",
        "api.example.com:8443/v1",
        "https://cdn.example.com/app.js",
        "/api/internal",
        "//api.example.com/protocol-relative",
    ]


def test_filter_external_urls_normalizes_target_domain_input():
    urls = [
        "https://example.com/",
        "https://api.example.com/",
        "https://evil-example.com/",
    ]

    assert recon_filters.filter_external_urls(urls, "https://*.example.com/") == [
        "https://example.com/",
        "https://api.example.com/",
    ]


def test_detect_path_explosion_uses_safer_threshold_and_logs(tmp_path):
    log = tmp_path / "filtered.log"

    assert recon_filters.detect_path_explosion("https://example.com/API/API/API/x", log_file=log) is False
    assert recon_filters.detect_path_explosion("https://example.com/API/API/API/API/x", log_file=log) is True
    assert "[PATH_EXPLOSION] https://example.com/API/API/API/API/x" in log.read_text(encoding="utf-8")


def test_filter_urls_batch_logs_external_urls_and_keeps_original_input(tmp_path):
    src = tmp_path / "all.txt"
    out = tmp_path / "all_filtered.txt"
    log = tmp_path / "filter.log"
    src.write_text(
        "\n".join(
            [
                "https://example.com/",
                "https://api.example.com:8443/v1",
                "https://cdn.example.com/app.js",
                "https://evil-example.com/",
                "https://example.com/a/a/a/a",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    stats = recon_filters.filter_urls_batch(src, out, "example.com", log_file=log)

    assert stats == {
        "total": 5,
        "kept": 3,
        "removed_external": 1,
        "removed_explosion": 1,
        "removed_encoding_errors": 0,
        "removed_html_encoding": 0,
        "removed_js_path_artifacts": 0,
        "removed_malformed_paths": 0,
        "removed_invalid": 0,
        "removed_duplicates": 0,
        "removed_cache_only": 0,
        "removed_shape_overflow": 0,
        "sanitized_attack_probes": 0,
        "normalized_cache_params": 0,
    }
    assert out.read_text(encoding="utf-8").splitlines() == [
        "https://example.com/",
        "https://api.example.com:8443/v1",
        "https://cdn.example.com/app.js",
    ]
    assert src.read_text(encoding="utf-8").splitlines()[0] == "https://example.com/"
    log_text = log.read_text(encoding="utf-8")
    assert "[EXTERNAL] https://evil-example.com/" in log_text
    assert "[PATH_EXPLOSION] https://example.com/a/a/a/a" in log_text


def test_main_handles_empty_input_without_dividing_by_zero(tmp_path, capsys):
    src = tmp_path / "empty.txt"
    out = tmp_path / "out.txt"
    src.write_text("", encoding="utf-8")

    rc = recon_filters.main([str(src), str(out), "example.com"])

    assert rc == 0
    assert out.read_text(encoding="utf-8") == ""
    assert "Kept: 0 (0.0%)" in capsys.readouterr().out


def test_cache_param_detection_keeps_api_version_context():
    assert recon_filters.is_cache_param_in_context("https://example.com/api/users?v=1", "v") is False
    assert recon_filters.is_cache_param_in_context("https://example.com/static/app.js?v=1", "v") is True


def test_business_lifecycle_parameters_are_not_treated_as_cache_noise(tmp_path):
    src = tmp_path / "all.txt"
    out = tmp_path / "all_filtered.txt"
    urls = [
        "https://example.com/oauth/callback?state=one",
        "https://example.com/oauth/callback?state=two",
        "https://example.com/download?hash=one",
        "https://example.com/download?hash=two",
        "https://example.com/api/search?nonce=one&timestamp=1",
        "https://example.com/api/search?nonce=two&timestamp=2",
    ]
    src.write_text("\n".join(urls) + "\n", encoding="utf-8")

    stats = recon_filters.filter_urls_batch(src, out, "example.com")

    assert stats["kept"] == len(urls)
    assert stats["removed_cache_only"] == 0
    assert out.read_text(encoding="utf-8").splitlines() == urls


def test_filter_urls_batch_removes_invalid_and_cache_only_duplicates(tmp_path):
    src = tmp_path / "all.txt"
    out = tmp_path / "all_filtered.txt"
    log = tmp_path / "filter.log"
    src.write_text(
        "\n".join([
            "javascript:alert(1)",
            "https://example.com/items?id=1&utm_source=a",
            "https://example.com/items?id=1&utm_source=b",
            "https://example.com/items?id=1&utm_medium=email",
            "https://example.com/items?id=2#first",
            "https://example.com/items?id=2#second",
        ]) + "\n",
        encoding="utf-8",
    )
    stats = recon_filters.filter_urls_batch(src, out, "example.com", log_file=log)
    assert stats["removed_invalid"] == 1
    assert stats["removed_duplicates"] == 3
    assert stats["removed_cache_only"] == 2
    assert out.read_text(encoding="utf-8").splitlines() == [
        "https://example.com/items?id=1",
        "https://example.com/items?id=2#first",
    ]


def test_filter_urls_batch_bounds_repeated_surface_shapes(tmp_path):
    src = tmp_path / "all.txt"
    out = tmp_path / "all_filtered.txt"
    src.write_text(
        "\n".join(f"https://example.com/users/{value}?view=full" for value in range(20, 32)) + "\n",
        encoding="utf-8",
    )
    stats = recon_filters.filter_urls_batch(src, out, "example.com", max_per_shape=3)
    assert stats["kept"] == 3
    assert stats["removed_shape_overflow"] == 9
    assert len(out.read_text(encoding="utf-8").splitlines()) == 3


def test_filter_urls_batch_keeps_all_shape_variants_by_default(tmp_path):
    src = tmp_path / "all.txt"
    out = tmp_path / "active.txt"
    src.write_text(
        "\n".join(f"https://example.com/users/{value}?view=full" for value in range(20, 32)) + "\n",
        encoding="utf-8",
    )

    stats = recon_filters.filter_urls_batch(src, out, "example.com")

    assert stats["kept"] == 12
    assert stats["removed_shape_overflow"] == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == 12


def test_filter_urls_batch_logs_encoding_artifacts(tmp_path):
    src = tmp_path / "all.txt"
    out = tmp_path / "all_filtered.txt"
    log = tmp_path / "filter.log"
    src.write_text(
        "\n".join(
            [
                "https://example.com/ok",
                "https://example.com/a%5Cn/b",
                "https://example.com/%5Cu003cscript%5Cu003e",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    stats = recon_filters.filter_urls_batch(src, out, "example.com", log_file=log)

    assert stats["kept"] == 1
    assert stats["removed_encoding_errors"] == 1
    assert stats["removed_html_encoding"] == 1
    assert out.read_text(encoding="utf-8").splitlines() == ["https://example.com/ok"]
    log_text = log.read_text(encoding="utf-8")
    assert "[ENCODING_ERROR] https://example.com/a%5Cn/b" in log_text
    assert "[HTML_ENCODING] https://example.com/%5Cu003cscript%5Cu003e" in log_text


def test_main_supports_log_file_and_path_explosion_switch(tmp_path, capsys):
    src = tmp_path / "all.txt"
    out = tmp_path / "all_filtered.txt"
    log = tmp_path / "filter.log"
    src.write_text(
        "https://example.com/a/a/a/a\nhttps://evil-example.com/\n",
        encoding="utf-8",
    )

    rc = recon_filters.main([
        str(src),
        str(out),
        "example.com",
        "--log-file",
        str(log),
        "--no-path-explosion",
    ])

    assert rc == 0
    assert out.read_text(encoding="utf-8").splitlines() == ["https://example.com/a/a/a/a"]
    assert "[EXTERNAL] https://evil-example.com/" in log.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    assert "Removed encoding errors: 0" in output
    assert "Removed HTML encoding: 0" in output
    assert "Removed JS path artifacts: 0" in output
    assert "Removed malformed paths: 0" in output


def test_filter_urls_batch_removes_js_member_expression_path_artifacts(tmp_path):
    src = tmp_path / "all.txt"
    out = tmp_path / "all_filtered.txt"
    log = tmp_path / "filter.log"
    src.write_text(
        "\n".join(
            [
                "https://example.com/i.visualViewport.scale/i.document.do",
                "https://example.com/r.dom.offsetHeight/r.do",
                "https://example.com/login.do",
                "https://example.com/assets/app.config.json",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    stats = recon_filters.filter_urls_batch(src, out, "example.com", log_file=log)

    assert stats["removed_js_path_artifacts"] == 2
    assert out.read_text(encoding="utf-8").splitlines() == [
        "https://example.com/login.do",
        "https://example.com/assets/app.config.json",
    ]
    log_text = log.read_text(encoding="utf-8")
    assert "[JS_PATH_ARTIFACT] https://example.com/i.visualViewport.scale/i.document.do" in log_text
    assert "[JS_PATH_ARTIFACT] https://example.com/r.dom.offsetHeight/r.do" in log_text


def test_filter_urls_batch_demotes_unbalanced_path_without_changing_raw_input(tmp_path):
    src = tmp_path / "all.txt"
    out = tmp_path / "all_filtered.txt"
    log = tmp_path / "filter.log"
    malformed = "https://example.com/dom/index.html.[10"
    valid = "https://example.com/dom/index.html"
    src.write_text(f"{malformed}\n{valid}\n", encoding="utf-8")

    stats = recon_filters.filter_urls_batch(src, out, "example.com", log_file=log)

    assert stats["removed_malformed_paths"] == 1
    assert out.read_text(encoding="utf-8").splitlines() == [valid]
    assert src.read_text(encoding="utf-8").splitlines() == [malformed, valid]
    assert f"[MALFORMED_PATH] {malformed}" in log.read_text(encoding="utf-8")


def test_active_view_sanitizes_probe_and_cache_values_without_dropping_shape(tmp_path):
    src = tmp_path / "raw.txt"
    out = tmp_path / "active.txt"
    summary = tmp_path / "filter_summary.json"
    log = tmp_path / "filter.log"
    opaque = "A" * 1200
    src.write_text(
        "\n".join(
            [
                "https://example.com/search?q=<script>alert(1)</script>&utm_source=x",
                f"https://example.com/import?token={opaque}",
                "https://example.com/import?token=B",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    stats = recon_filters.filter_urls_batch(
        src, out, "example.com", log_file=log, summary_file=summary, max_per_shape=2
    )

    assert stats["sanitized_attack_probes"] == 1
    assert stats["normalized_cache_params"] == 1
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "https://example.com/search?q=__probe__"
    assert lines[1].startswith("https://example.com/import?token=")
    assert len(lines[1]) > 1000
    assert lines[2] == "https://example.com/import?token=B"
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["kept"] == 3
    assert len(log.read_text(encoding="utf-8").splitlines()) <= 64
    assert payload["output_sha256"]


def test_active_view_keeps_encoded_and_duplicate_query_variants(tmp_path):
    src = tmp_path / "raw.txt"
    out = tmp_path / "active.txt"
    src.write_text(
        "\n".join(
            [
                "https://example.com/search?q=a%2Fb",
                "https://example.com/search?q=a+b",
                "https://example.com/search?id=1&id=2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    recon_filters.filter_urls_batch(src, out, "example.com")

    assert out.read_text(encoding="utf-8").splitlines() == [
        "https://example.com/search?q=a%2Fb",
        "https://example.com/search?q=a+b",
        "https://example.com/search?id=1&id=2",
    ]


def test_filter_publication_failure_preserves_previous_active(tmp_path):
    src = tmp_path / "missing.txt"
    out = tmp_path / "active.txt"
    out.write_text("https://example.com/previous\n", encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        recon_filters.filter_urls_batch(src, out, "example.com")

    assert out.read_text(encoding="utf-8") == "https://example.com/previous\n"
    assert not list(tmp_path.glob(".active.txt.*.tmp"))
