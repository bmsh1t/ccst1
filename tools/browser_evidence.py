#!/usr/bin/env python3
"""Capture minimal browser-state evidence through playwright-cli."""

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"
DEFAULT_RECON_ROOT = BASE_DIR / "recon"
PLAYWRIGHT_BIN = "playwright-cli"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_part(value: str, default: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip()).strip("._-")
    return normalized[:120] or default


def _target_key(target: str) -> str:
    return _safe_part(target.replace("/", "_"), "unknown-target")


def default_browser_session(target: str) -> str:
    """Return a stable playwright-cli session name for a target."""
    return f"browser-{_target_key(target)}"


def _run_cli(args: list[str], *, session: str, timeout: int) -> dict:
    cmd = [PLAYWRIGHT_BIN, f"-s={session}", *args]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        return {
            "name": " ".join(args),
            "cmd": cmd,
            "returncode": completed.returncode,
            "success": completed.returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
            "stderr_bytes": len(stderr.encode("utf-8", errors="replace")),
        }
    except Exception as exc:
        return {
            "name": " ".join(args),
            "cmd": cmd,
            "returncode": None,
            "success": False,
            "stdout": "",
            "stderr": str(exc),
            "stdout_bytes": 0,
            "stderr_bytes": len(str(exc).encode("utf-8", errors="replace")),
        }


def _compact_step(step: dict) -> dict:
    return {
        "name": step["name"],
        "cmd": step["cmd"],
        "returncode": step["returncode"],
        "success": step["success"],
        "stdout_bytes": step["stdout_bytes"],
        "stderr_bytes": step["stderr_bytes"],
        "stderr_preview": step["stderr"][:300],
    }


def _parse_jsonish(raw: str) -> object:
    value = (raw or "").strip()
    if not value:
        return []
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {"raw": value}


def _count_items(payload: object) -> int:
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("items", "requests", "entries", "messages"):
            if isinstance(payload.get(key), list):
                return len(payload[key])
        raw = payload.get("raw")
        if isinstance(raw, str):
            return len([line for line in raw.splitlines() if line.strip()])
    return 0


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _record_text_artifact(capture_dir: Path, filename: str, step: dict, artifacts: dict) -> None:
    if not step["success"]:
        return
    path = capture_dir / filename
    path.write_text(step["stdout"], encoding="utf-8")
    artifacts[filename.replace(".", "_")] = str(path)


def _record_json_artifact(capture_dir: Path, filename: str, step: dict, artifacts: dict) -> int:
    if not step["success"]:
        return 0
    payload = _parse_jsonish(step["stdout"])
    path = capture_dir / filename
    _write_json(path, payload)
    artifacts[filename.replace(".", "_")] = str(path)
    return _count_items(payload)


def _record_storage(capture_dir: Path, local_step: dict, session_step: dict, artifacts: dict) -> None:
    if not local_step["success"] and not session_step["success"]:
        return
    payload = {
        "localStorage": _parse_jsonish(local_step["stdout"]) if local_step["success"] else [],
        "sessionStorage": _parse_jsonish(session_step["stdout"]) if session_step["success"] else [],
    }
    path = capture_dir / "storage.json"
    _write_json(path, payload)
    artifacts["storage_json"] = str(path)


def _record_existing_file(path: Path, key: str, artifacts: dict) -> None:
    if path.is_file():
        artifacts[key] = str(path)


def _derive_recon_root(evidence_root: Path) -> Path:
    """Return the recon root paired with the selected evidence root."""
    if evidence_root == DEFAULT_EVIDENCE_ROOT:
        return DEFAULT_RECON_ROOT
    if evidence_root.name == "evidence":
        return evidence_root.parent / "recon"
    return DEFAULT_RECON_ROOT


def _write_browser_surface(
    *,
    target_name: str,
    evidence_root: Path,
    capture_dir: Path,
    artifacts: dict,
) -> dict:
    try:
        from browser_surface import build_page_js_map, write_browser_surface
    except ImportError:  # pragma: no cover - package import path
        from tools.browser_surface import build_page_js_map, write_browser_surface

    surface = write_browser_surface(
        recon_root=_derive_recon_root(evidence_root),
        target_key=target_name,
        requests_path=artifacts.get("requests_json", ""),
        snapshot_path=artifacts.get("snapshot_txt", ""),
        capture_dir=str(capture_dir),
    )
    # Refresh the per-page JS map after every capture so /surface and /hunt
    # can answer "which page loads this JS file?" without re-visiting.
    # Fail-soft: if the map build raises (corrupt summary, etc.), we keep
    # the rest of the capture flow alive.
    try:
        build_page_js_map(
            evidence_root=evidence_root,
            recon_root=_derive_recon_root(evidence_root),
            target_key=target_name,
        )
    except (OSError, json.JSONDecodeError):  # pragma: no cover - defensive
        pass
    return surface


def capture_browser_evidence(
    target: str,
    url: str,
    *,
    session: str = "",
    label: str = "capture",
    evidence_root: str | Path | None = None,
    timeout: int = 30,
    capture_screenshot: bool = False,
) -> dict:
    """Capture minimal browser evidence for one URL without closing the session."""
    target_name = _target_key(target)
    safe_label = _safe_part(label, "capture")
    session_name = session.strip() or default_browser_session(target_name)
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    browser_root = root / target_name / "browser"
    capture_dir = browser_root / f"{_timestamp_slug()}-{safe_label}"
    capture_dir.mkdir(parents=True, exist_ok=True)

    steps: list[dict] = []
    artifacts: dict[str, str] = {}
    counts = {"requests": 0, "console": 0}

    # Prefer an existing named session; create/open one if it is not active yet.
    goto_step = _run_cli(["goto", url], session=session_name, timeout=timeout)
    steps.append(goto_step)
    if not goto_step["success"]:
        steps.append(_run_cli(["open", url], session=session_name, timeout=timeout))

    snapshot_step = _run_cli(["--raw", "snapshot"], session=session_name, timeout=timeout)
    steps.append(snapshot_step)
    _record_text_artifact(capture_dir, "snapshot.txt", snapshot_step, artifacts)

    requests_step = _run_cli(["--raw", "requests"], session=session_name, timeout=timeout)
    steps.append(requests_step)
    counts["requests"] = _record_json_artifact(capture_dir, "requests.json", requests_step, artifacts)
    browser_surface = _write_browser_surface(
        target_name=target_name,
        evidence_root=root,
        capture_dir=capture_dir,
        artifacts=artifacts,
    )
    browser_counts = browser_surface.get("counts") if isinstance(browser_surface, dict) else {}
    if isinstance(browser_counts, dict):
        counts["browser_xhr_endpoints"] = int(browser_counts.get("xhr_endpoints", 0) or 0)
        counts["browser_api_endpoints"] = int(browser_counts.get("api_endpoints", 0) or 0)
        counts["browser_params"] = int(browser_counts.get("browser_params", 0) or 0)

    console_step = _run_cli(["--raw", "console"], session=session_name, timeout=timeout)
    steps.append(console_step)
    counts["console"] = _record_json_artifact(capture_dir, "console.json", console_step, artifacts)

    cookies_step = _run_cli(["--raw", "cookie-list"], session=session_name, timeout=timeout)
    steps.append(cookies_step)
    _record_json_artifact(capture_dir, "cookies.json", cookies_step, artifacts)

    local_step = _run_cli(["--raw", "localstorage-list"], session=session_name, timeout=timeout)
    session_step = _run_cli(["--raw", "sessionstorage-list"], session=session_name, timeout=timeout)
    steps.extend([local_step, session_step])
    _record_storage(capture_dir, local_step, session_step, artifacts)

    state_path = capture_dir / "state.json"
    state_step = _run_cli(["state-save", str(state_path)], session=session_name, timeout=timeout)
    steps.append(state_step)
    _record_existing_file(state_path, "state_json", artifacts)

    if capture_screenshot:
        screenshot_path = capture_dir / "screenshot.png"
        screenshot_step = _run_cli(
            ["screenshot", f"--filename={screenshot_path}"],
            session=session_name,
            timeout=timeout,
        )
        steps.append(screenshot_step)
        _record_existing_file(screenshot_path, "screenshot_png", artifacts)

    summary_path = capture_dir / "summary.json"
    pointer_path = browser_root / "last-capture.json"
    summary = {
        "target": target,
        "target_key": target_name,
        "url": url,
        "session": session_name,
        "label": safe_label,
        "captured_at": _now_utc(),
        "evidence_dir": str(capture_dir),
        "summary_path": str(summary_path),
        "pointer_path": str(pointer_path),
        "success": any(step["success"] for step in steps[:2]),
        "capture_screenshot": bool(capture_screenshot),
        "counts": counts,
        "artifacts": artifacts,
        "browser_surface": browser_surface,
        "steps": [_compact_step(step) for step in steps],
    }
    _write_json(summary_path, summary)

    pointer = compact_browser_evidence(summary)
    pointer.update({"target": target, "target_key": target_name, "label": safe_label})
    _write_json(pointer_path, pointer)
    return summary


def _read_summary_from_path(path: str | Path) -> dict:
    candidate = Path(path)
    summary_path = candidate / "summary.json" if candidate.is_dir() else candidate
    if not summary_path.is_file():
        return {}
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def compact_browser_evidence(summary: dict | str | Path | None) -> dict:
    """Return validation-safe browser evidence linkage fields only."""
    if not summary:
        return {}
    payload = _read_summary_from_path(summary) if isinstance(summary, (str, Path)) else summary
    if not isinstance(payload, dict) or not payload:
        return {}

    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    compact = {
        "dir": payload.get("evidence_dir") or payload.get("dir") or "",
        "summary_path": payload.get("summary_path") or payload.get("summary") or "",
        "session": payload.get("session") or "",
        "url": payload.get("url") or "",
        "request_count": int(counts.get("requests", payload.get("request_count", 0)) or 0),
        "console_count": int(counts.get("console", payload.get("console_count", 0)) or 0),
        "screenshot_path": artifacts.get("screenshot_png") or payload.get("screenshot_path") or "",
        "captured_at": payload.get("captured_at") or "",
        "error": payload.get("error") or "",
    }
    browser_surface = payload.get("browser_surface") if isinstance(payload.get("browser_surface"), dict) else {}
    browser_counts = browser_surface.get("counts") if isinstance(browser_surface.get("counts"), dict) else {}
    browser_artifacts = browser_surface.get("artifacts") if isinstance(browser_surface.get("artifacts"), dict) else {}
    compact.update({
        "browser_xhr_count": int(browser_counts.get("xhr_endpoints", payload.get("browser_xhr_count", 0)) or 0),
        "browser_api_count": int(browser_counts.get("api_endpoints", payload.get("browser_api_count", 0)) or 0),
        "browser_param_count": int(browser_counts.get("browser_params", payload.get("browser_param_count", 0)) or 0),
        "browser_surface_summary": browser_artifacts.get("summary") or payload.get("browser_surface_summary") or "",
    })
    return {key: value for key, value in compact.items() if value not in ("", None)}


def load_last_browser_evidence(target: str, *, evidence_root: str | Path | None = None) -> dict:
    """Load compact linkage for the most recent capture of a target."""
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    pointer_path = root / _target_key(target) / "browser" / "last-capture.json"
    if not pointer_path.is_file():
        return {}
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(pointer, dict):
        return {}
    summary_path = pointer.get("summary_path")
    if summary_path:
        return compact_browser_evidence(summary_path)
    return compact_browser_evidence(pointer)
