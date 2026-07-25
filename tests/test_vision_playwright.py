"""Chrome DevTools/Playwright MCP 截图读取回归。"""

from __future__ import annotations

import json
from pathlib import Path

from tools import vision_browser


def _write_capture(
    evidence_root: Path,
    *,
    run_id: str,
    captured_at: str,
    screenshot: Path,
    snapshot: Path | None = None,
) -> None:
    capture_dir = evidence_root / "x.com" / "browser" / run_id
    capture_dir.mkdir(parents=True)
    artifacts = {"screenshot_png": str(screenshot)}
    if snapshot:
        artifacts["snapshot_private_txt"] = str(snapshot)
    (capture_dir / "summary.json").write_text(
        json.dumps({
            "captured_at": captured_at,
            "evidence_dir": str(capture_dir),
            "url": f"https://x.com/{run_id}",
            "artifacts": artifacts,
        }),
        encoding="utf-8",
    )


def test_list_screenshots_reads_imported_summary_artifacts(tmp_path):
    private_dir = tmp_path / ".private" / "browser" / "x.com"
    private_dir.mkdir(parents=True)
    first_png = private_dir / "first.png"
    second_png = private_dir / "second.png"
    snapshot = private_dir / "snapshot.txt"
    first_png.write_bytes(b"first")
    second_png.write_bytes(b"second")
    snapshot.write_text("<main>second</main>", encoding="utf-8")
    _write_capture(
        tmp_path,
        run_id="second",
        captured_at="2026-07-25T02:00:00Z",
        screenshot=second_png,
        snapshot=snapshot,
    )
    _write_capture(
        tmp_path,
        run_id="first",
        captured_at="2026-07-25T01:00:00Z",
        screenshot=first_png,
    )

    rows = vision_browser.list_screenshots("x.com", evidence_root=tmp_path)

    assert [row["seq"] for row in rows] == [1, 2]
    assert rows[0]["screenshot_path"] == str(first_png)
    assert rows[0]["dom_path"] == ""
    assert rows[1]["screenshot_path"] == str(second_png)
    assert rows[1]["dom_path"] == str(snapshot)
    assert vision_browser.find_latest_screenshot("x.com", evidence_root=tmp_path) == second_png


def test_list_screenshots_ignores_invalid_or_missing_artifacts(tmp_path):
    browser_dir = tmp_path / "x.com" / "browser"
    invalid_dir = browser_dir / "invalid"
    missing_dir = browser_dir / "missing"
    invalid_dir.mkdir(parents=True)
    missing_dir.mkdir(parents=True)
    (invalid_dir / "summary.json").write_text("{", encoding="utf-8")
    (missing_dir / "summary.json").write_text(
        json.dumps({"artifacts": {"screenshot_png": str(tmp_path / "missing.png")}}),
        encoding="utf-8",
    )

    assert vision_browser.list_screenshots("x.com", evidence_root=tmp_path) == []
    assert vision_browser.find_latest_screenshot("x.com", evidence_root=tmp_path) is None
