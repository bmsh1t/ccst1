"""Reproduce baseline contract gaps using temporary files, without scans or installation."""

import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.autopilot_gate import _scanner_lane_residuals
from tools.autopilot_state_read import _load_scanner_summary_projection
from tools.runtime_doctor import compare_kind


TARGET = "summary-contract.test"
REPO = Path(__file__).resolve().parents[4]


def scanner_cases(root):
    path = root / "findings" / TARGET / "summary.json"
    path.parent.mkdir(parents=True)
    lane = {
        "lane": "fixture", "status": "sampled", "execution_kind": "active_scanner",
        "input_total": 3, "selected": 2, "remaining": 1,
        "continuation": "review the remaining local fixture inputs", "closure_blocking": False,
    }
    cases = {
        "valid-residual": {"fixture": lane},
        "empty-lanes": {},
        "wrong-lane-container": [],
        "fractional-counts": {"fixture": {**lane, "input_total": 1.9, "selected": 1.1, "remaining": 0.8}},
        "infinite-count": {"fixture": {**lane, "input_total": float("inf")}},
    }
    results = {}
    for name, lanes in cases.items():
        payload = json.dumps({"target": TARGET, "lane_coverage": lanes}).encode()
        path.write_bytes(payload)
        try:
            projection = _load_scanner_summary_projection(str(root), TARGET)
            residuals = _scanner_lane_residuals({"scanner_summary": projection})
            results[name] = {"status": projection["status"], "residuals": len(residuals)}
        except (ValueError, OverflowError) as exc:
            results[name] = {"error": type(exc).__name__}
        assert path.read_bytes() == payload
    path.write_bytes(b"\xff\xfe")
    try:
        _load_scanner_summary_projection(str(root), TARGET)
    except UnicodeError as exc:
        results["bad-utf8"] = {"error": type(exc).__name__}
    else:
        raise AssertionError("Expected the baseline UTF-8 decoding gap")
    assert results["valid-residual"] == {"status": "valid", "residuals": 1}
    assert results["empty-lanes"] == {"status": "valid", "residuals": 0}
    assert results["wrong-lane-container"] == {"status": "missing", "residuals": 0}
    assert results["fractional-counts"] == {"status": "valid", "residuals": 0}
    assert results["infinite-count"] == {"error": "OverflowError"}
    return results


def file_selection_case(root):
    source = root / "source"
    destination = root / "fixture-home"
    for kind in ("commands", "agents"):
        directory = source / kind
        directory.mkdir(parents=True)
        for name in ("autopilot.md", "local.patch.md", "local.PATCH.md"):
            (directory / name).write_text("local fixture content\n")
    script = (REPO / "install.sh").read_text()
    start = script.index("# Install commands\n")
    end = script.index('echo "Done! Skills installed', start)
    copy_loops = script[start:end]
    result = subprocess.run(
        ["/bin/bash", "-euo", "pipefail", "-c", copy_loops],
        env={**os.environ, "HOME": str(destination), "SCRIPT_DIR": str(source)},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True,
    )
    assert result.returncode == 0
    findings = {}
    for kind in ("commands", "agents"):
        comparison = compare_kind(source, destination / ".claude", kind)
        findings[kind] = {item["relative_path"]: item["status"] for item in comparison["items"]}
    assert findings["commands"] == {
        "autopilot.md": "ok", "local.patch.md": "extra", "local.PATCH.md": "extra",
    }
    assert findings["agents"] == {"autopilot.md": "ok", "local.PATCH.md": "extra"}
    return findings


if __name__ == "__main__":
    with TemporaryDirectory(prefix="scanner-deployment-contract-") as directory:
        root = Path(directory)
        print(json.dumps({
            "scanner": scanner_cases(root),
            "file_selection": file_selection_case(root),
        }, ensure_ascii=False, indent=2))
