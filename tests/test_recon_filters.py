from pathlib import Path

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
