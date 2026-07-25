"""浏览器 MCP 证据摘要辅助函数回归测试。"""

import json
from pathlib import Path

from tools import browser_evidence


def test_snapshot_shape_keeps_form_shape_without_secret_body():
    secret = "SECRET_BROWSER_FIXTURE"
    shaped = browser_evidence.snapshot_shape(
        f'<form action="/submit?token={secret}" method="post">{secret}</form>'
    )

    assert 'form action="/submit" method="POST"' in shaped
    assert "snapshot_sha256=" in shaped
    assert secret not in shaped


def test_console_shape_only_keeps_count_types_and_digest():
    payload = [
        {"type": "log", "text": "sensitive body"},
        {"type": "error", "text": "another body"},
    ]

    shaped = browser_evidence.console_shape(payload)

    assert shaped["count"] == 2
    assert shaped["types"] == ["error", "log"]
    assert len(shaped["sha256"]) == 64
    assert "sensitive body" not in json.dumps(shaped)


def test_compact_browser_evidence_reads_mcp_summary_directory(tmp_path):
    capture_dir = tmp_path / "capture"
    capture_dir.mkdir()
    summary_path = capture_dir / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "evidence_dir": str(capture_dir),
                "summary_path": str(summary_path),
                "capture_backend": "chrome-devtools-mcp",
                "url": "https://target.local/app",
                "counts": {"requests": 3, "console": 1},
                "browser_surface": {
                    "counts": {"xhr_endpoints": 2, "api_endpoints": 1, "browser_params": 4},
                    "artifacts": {"summary": "/tmp/browser-summary.json"},
                },
            }
        ),
        encoding="utf-8",
    )

    compact = browser_evidence.compact_browser_evidence(capture_dir)

    assert compact["capture_backend"] == "chrome-devtools-mcp"
    assert compact["request_count"] == 3
    assert compact["browser_xhr_count"] == 2
    assert compact["browser_param_count"] == 4


def test_load_last_browser_evidence_follows_pointer(tmp_path):
    browser_dir = tmp_path / "target.local" / "browser"
    capture_dir = browser_dir / "capture"
    capture_dir.mkdir(parents=True)
    summary_path = capture_dir / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "evidence_dir": str(capture_dir),
                "summary_path": str(summary_path),
                "capture_backend": "playwright-mcp",
                "counts": {"requests": 1},
            }
        ),
        encoding="utf-8",
    )
    (browser_dir / "last-capture.json").write_text(
        json.dumps({"summary_path": str(summary_path)}),
        encoding="utf-8",
    )

    compact = browser_evidence.load_last_browser_evidence(
        "target.local",
        evidence_root=tmp_path,
    )

    assert compact["capture_backend"] == "playwright-mcp"
    assert compact["request_count"] == 1


def test_compact_browser_evidence_returns_empty_for_missing_or_invalid(tmp_path):
    invalid = tmp_path / "summary.json"
    invalid.write_text("not json", encoding="utf-8")

    assert browser_evidence.compact_browser_evidence(None) == {}
    assert browser_evidence.compact_browser_evidence(invalid) == {}
    assert browser_evidence.load_last_browser_evidence("missing.local", evidence_root=tmp_path) == {}
