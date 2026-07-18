#!/usr/bin/env python3
"""通过 agent-browser 或 playwright-cli 采集统一的浏览器态证据。"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_EVIDENCE_ROOT = BASE_DIR / "evidence"
DEFAULT_RECON_ROOT = BASE_DIR / "recon"
AGENT_BROWSER_BIN = "agent-browser"
PLAYWRIGHT_BIN = "playwright-cli"
SUPPORTED_BACKENDS = (AGENT_BROWSER_BIN, PLAYWRIGHT_BIN)

Which = Callable[[str], str | None]


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_part(value: str, default: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip()).strip("._-")
    return normalized[:120] or default


def _target_key(target: str) -> str:
    """Return the shared canonical storage key for browser artifacts."""
    try:
        from target_paths import target_storage_key
    except ImportError:  # pragma: no cover - package import path
        from tools.target_paths import target_storage_key

    try:
        return target_storage_key(target)
    except ValueError:
        # Keep browser capture fail-soft for malformed/manual labels while all
        # valid URL/domain/IP targets use the project-wide canonical key.
        return _safe_part(target.replace("/", "_"), "unknown-target")


def _session_key(target: str) -> str:
    """返回独立于磁盘 key 的稳定浏览器 session 名片段。"""
    return _safe_part(target.replace("/", "_"), "unknown-target")[:64]


def default_browser_session(target: str) -> str:
    """返回目标级稳定浏览器 session 名。"""
    return f"browser-{_session_key(target)}"


def resolve_browser_backend(backend: str = "auto", *, which: Which = shutil.which) -> str:
    """解析单次 capture 使用的 backend；选择后不再中途切换。"""
    normalized = str(backend or "auto").strip().lower()
    if normalized in SUPPORTED_BACKENDS:
        return normalized
    if normalized != "auto":
        raise ValueError(f"Unsupported browser backend: {backend}")
    for candidate in SUPPORTED_BACKENDS:
        if which(candidate):
            return candidate
    raise RuntimeError("No supported browser backend found: agent-browser or playwright-cli")


def _run_subprocess(
    cmd: list[str],
    *,
    name: str,
    timeout: int,
    env: dict[str, str],
    require_json_success: bool = False,
) -> dict:
    """运行浏览器 CLI，并把进程和 JSON 协议错误统一成 step。"""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        success = completed.returncode == 0
        if require_json_success:
            envelope = _parse_jsonish(stdout)
            protocol_success = isinstance(envelope, dict) and envelope.get("success") is True
            success = success and protocol_success
            if isinstance(envelope, dict) and not protocol_success and not stderr:
                error = envelope.get("error")
                stderr = str(error or "Invalid agent-browser JSON response")
        return {
            "name": name,
            "cmd": cmd,
            "returncode": completed.returncode,
            "success": success,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
            "stderr_bytes": len(stderr.encode("utf-8", errors="replace")),
        }
    except Exception as exc:
        return {
            "name": name,
            "cmd": cmd,
            "returncode": None,
            "success": False,
            "stdout": "",
            "stderr": str(exc),
            "stdout_bytes": 0,
            "stderr_bytes": len(str(exc).encode("utf-8", errors="replace")),
        }


def _run_playwright_cli(args: list[str], *, session: str, timeout: int) -> dict:
    cmd = [PLAYWRIGHT_BIN, f"-s={session}", *args]
    env = os.environ.copy()
    # Codex/CI 可能把 ~/.cache 设为只读，因此只重定向 daemon/session 运行文件。
    if not env.get("PLAYWRIGHT_DAEMON_SESSION_DIR"):
        daemon_dir = Path(tempfile.gettempdir()) / "ccst-playwright-daemon"
        daemon_dir.mkdir(parents=True, exist_ok=True)
        env["PLAYWRIGHT_DAEMON_SESSION_DIR"] = str(daemon_dir)
    return _run_subprocess(cmd, name=" ".join(args), timeout=timeout, env=env)


def _run_agent_browser_cli(args: list[str], *, session: str, timeout: int) -> dict:
    cmd = [AGENT_BROWSER_BIN, "--session", session, "--json", *args]
    env = os.environ.copy()
    # 默认 /run/user/<uid> 在部分 CLI sandbox 中只读；短路径同时避免 Unix socket 超长。
    if not env.get("AGENT_BROWSER_SOCKET_DIR"):
        socket_dir = Path(tempfile.gettempdir()) / "ccst-ab"
        socket_dir.mkdir(parents=True, exist_ok=True)
        env["AGENT_BROWSER_SOCKET_DIR"] = str(socket_dir)
    return _run_subprocess(
        cmd,
        name=" ".join(args),
        timeout=timeout,
        env=env,
        require_json_success=True,
    )


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


def _record_agent_raw(
    capture_dir: Path,
    stem: str,
    step: dict,
    artifacts: dict[str, str],
) -> object:
    """保存 agent-browser 原始 envelope，失败响应也保留。"""
    payload = _parse_jsonish(step.get("stdout", ""))
    if payload == [] and not step.get("stdout"):
        payload = {
            "success": False,
            "data": None,
            "error": step.get("stderr", "") or "No JSON response",
        }
    path = capture_dir / f"{stem}.raw.json"
    _write_json(path, payload)
    artifacts[f"{stem.replace('-', '_')}_raw_json"] = str(path)
    return payload


def _agent_data(envelope: object) -> object:
    if isinstance(envelope, dict):
        return envelope.get("data")
    return None


def _agent_storage_values(payload: object) -> object:
    """去掉 agent-browser storage 响应中的 lifecycle 包装，仅保留键值。"""
    if isinstance(payload, dict):
        for key in ("data", "storage"):
            value = payload.get(key)
            if isinstance(value, (dict, list)):
                return value
    return payload if payload is not None else {}


def _step_error(step: dict) -> str:
    return str(step.get("stderr", "") or "").strip()


def _capture_playwright_backend(
    *,
    url: str,
    session_name: str,
    capture_dir: Path,
    timeout: int,
    capture_screenshot: bool,
) -> dict:
    """执行原有 playwright-cli 协议，不改变命令和 artifact 语义。"""
    steps: list[dict] = []
    artifacts: dict[str, str] = {}
    counts = {"requests": 0, "console": 0}

    goto_step = _run_playwright_cli(["goto", url], session=session_name, timeout=timeout)
    steps.append(goto_step)
    navigation_steps = [goto_step]
    if not goto_step["success"]:
        open_step = _run_playwright_cli(["open", url], session=session_name, timeout=timeout)
        steps.append(open_step)
        navigation_steps.append(open_step)

    snapshot_step = _run_playwright_cli(["--raw", "snapshot"], session=session_name, timeout=timeout)
    steps.append(snapshot_step)
    _record_text_artifact(capture_dir, "snapshot.txt", snapshot_step, artifacts)

    requests_step = _run_playwright_cli(["--raw", "requests"], session=session_name, timeout=timeout)
    steps.append(requests_step)
    counts["requests"] = _record_json_artifact(capture_dir, "requests.json", requests_step, artifacts)

    console_step = _run_playwright_cli(["--raw", "console"], session=session_name, timeout=timeout)
    steps.append(console_step)
    counts["console"] = _record_json_artifact(capture_dir, "console.json", console_step, artifacts)

    cookies_step = _run_playwright_cli(["--raw", "cookie-list"], session=session_name, timeout=timeout)
    steps.append(cookies_step)
    _record_json_artifact(capture_dir, "cookies.json", cookies_step, artifacts)

    local_step = _run_playwright_cli(["--raw", "localstorage-list"], session=session_name, timeout=timeout)
    session_step = _run_playwright_cli(["--raw", "sessionstorage-list"], session=session_name, timeout=timeout)
    steps.extend([local_step, session_step])
    _record_storage(capture_dir, local_step, session_step, artifacts)

    state_path = capture_dir / "state.json"
    state_step = _run_playwright_cli(["state-save", str(state_path)], session=session_name, timeout=timeout)
    steps.append(state_step)
    _record_existing_file(state_path, "state_json", artifacts)

    if capture_screenshot:
        screenshot_path = capture_dir / "screenshot.png"
        screenshot_step = _run_playwright_cli(
            ["screenshot", f"--filename={screenshot_path}"],
            session=session_name,
            timeout=timeout,
        )
        steps.append(screenshot_step)
        _record_existing_file(screenshot_path, "screenshot_png", artifacts)

    success = any(step["success"] for step in navigation_steps)
    error = "" if success else next((_step_error(step) for step in navigation_steps if _step_error(step)), "")
    return {"steps": steps, "artifacts": artifacts, "counts": counts, "success": success, "error": error}


def _capture_agent_browser_backend(
    *,
    url: str,
    session_name: str,
    capture_dir: Path,
    timeout: int,
    capture_screenshot: bool,
) -> dict:
    """执行 agent-browser 结构化采集，并保留 raw envelope 与规范化 artifact。"""
    steps: list[dict] = []
    artifacts: dict[str, str] = {}
    counts = {"requests": 0, "console": 0}

    open_step = _run_agent_browser_cli(["open"], session=session_name, timeout=timeout)
    steps.append(open_step)
    _record_agent_raw(capture_dir, "open", open_step, artifacts)

    # 命名 session 会跨 capture 保留日志；导航前清空，避免把旧页面请求归到本次 URL。
    requests_clear_step = _run_agent_browser_cli(
        ["network", "requests", "--clear"],
        session=session_name,
        timeout=timeout,
    )
    steps.append(requests_clear_step)
    _record_agent_raw(capture_dir, "requests-clear", requests_clear_step, artifacts)

    console_clear_step = _run_agent_browser_cli(["console", "--clear"], session=session_name, timeout=timeout)
    steps.append(console_clear_step)
    _record_agent_raw(capture_dir, "console-clear", console_clear_step, artifacts)

    har_start_step = _run_agent_browser_cli(
        ["network", "har", "start"],
        session=session_name,
        timeout=timeout,
    )
    steps.append(har_start_step)
    _record_agent_raw(capture_dir, "har-start", har_start_step, artifacts)

    navigate_step = _run_agent_browser_cli(["navigate", url], session=session_name, timeout=timeout)
    steps.append(navigate_step)
    _record_agent_raw(capture_dir, "navigate", navigate_step, artifacts)

    snapshot_step = _run_agent_browser_cli(["snapshot"], session=session_name, timeout=timeout)
    steps.append(snapshot_step)
    snapshot_envelope = _record_agent_raw(capture_dir, "snapshot", snapshot_step, artifacts)
    if snapshot_step["success"]:
        snapshot_data = _agent_data(snapshot_envelope)
        snapshot_text = snapshot_data.get("snapshot", "") if isinstance(snapshot_data, dict) else ""
        if not isinstance(snapshot_text, str) or not snapshot_text:
            snapshot_text = json.dumps(snapshot_data, ensure_ascii=False, indent=2)
        snapshot_path = capture_dir / "snapshot.txt"
        snapshot_path.write_text(snapshot_text, encoding="utf-8")
        artifacts["snapshot_txt"] = str(snapshot_path)

    requests_step = _run_agent_browser_cli(["network", "requests"], session=session_name, timeout=timeout)
    steps.append(requests_step)
    requests_envelope = _record_agent_raw(capture_dir, "requests", requests_step, artifacts)
    if requests_step["success"]:
        requests_data = _agent_data(requests_envelope)
        if isinstance(requests_data, dict) and isinstance(requests_data.get("requests"), list):
            request_items = requests_data["requests"]
        elif isinstance(requests_data, list):
            request_items = requests_data
        else:
            request_items = []
        requests_path = capture_dir / "requests.json"
        _write_json(requests_path, {"requests": request_items, "source": AGENT_BROWSER_BIN})
        artifacts["requests_json"] = str(requests_path)
        counts["requests"] = len(request_items)

    console_step = _run_agent_browser_cli(["console"], session=session_name, timeout=timeout)
    steps.append(console_step)
    console_envelope = _record_agent_raw(capture_dir, "console", console_step, artifacts)
    if console_step["success"]:
        console_data = _agent_data(console_envelope)
        console_payload = console_data.get("messages", []) if isinstance(console_data, dict) else console_data
        console_path = capture_dir / "console.json"
        _write_json(console_path, console_payload if console_payload is not None else [])
        artifacts["console_json"] = str(console_path)
        counts["console"] = _count_items(console_data)

    cookies_step = _run_agent_browser_cli(["cookies", "get"], session=session_name, timeout=timeout)
    steps.append(cookies_step)
    cookies_envelope = _record_agent_raw(capture_dir, "cookies", cookies_step, artifacts)
    if cookies_step["success"]:
        cookies_data = _agent_data(cookies_envelope)
        cookies_payload = cookies_data.get("cookies", []) if isinstance(cookies_data, dict) else cookies_data
        cookies_path = capture_dir / "cookies.json"
        _write_json(cookies_path, cookies_payload if cookies_payload is not None else [])
        artifacts["cookies_json"] = str(cookies_path)

    local_step = _run_agent_browser_cli(["storage", "local"], session=session_name, timeout=timeout)
    session_step = _run_agent_browser_cli(["storage", "session"], session=session_name, timeout=timeout)
    steps.extend([local_step, session_step])
    local_envelope = _record_agent_raw(capture_dir, "local-storage", local_step, artifacts)
    session_envelope = _record_agent_raw(capture_dir, "session-storage", session_step, artifacts)
    if local_step["success"] or session_step["success"]:
        storage_payload = {
            "localStorage": _agent_storage_values(_agent_data(local_envelope)) if local_step["success"] else {},
            "sessionStorage": _agent_storage_values(_agent_data(session_envelope)) if session_step["success"] else {},
        }
        storage_path = capture_dir / "storage.json"
        _write_json(storage_path, storage_payload)
        artifacts["storage_json"] = str(storage_path)

    state_path = capture_dir / "state.json"
    state_step = _run_agent_browser_cli(["state", "save", str(state_path)], session=session_name, timeout=timeout)
    steps.append(state_step)
    _record_agent_raw(capture_dir, "state", state_step, artifacts)
    _record_existing_file(state_path, "state_json", artifacts)

    core_steps = [
        open_step,
        requests_clear_step,
        console_clear_step,
        navigate_step,
        snapshot_step,
        requests_step,
        console_step,
        cookies_step,
        local_step,
        session_step,
        state_step,
    ]
    if capture_screenshot:
        screenshot_path = capture_dir / "screenshot.png"
        screenshot_step = _run_agent_browser_cli(
            ["screenshot", str(screenshot_path)],
            session=session_name,
            timeout=timeout,
        )
        steps.append(screenshot_step)
        _record_agent_raw(capture_dir, "screenshot", screenshot_step, artifacts)
        _record_existing_file(screenshot_path, "screenshot_png", artifacts)
        core_steps.append(screenshot_step)

    har_path = capture_dir / "network.har"
    har_stop_step = _run_agent_browser_cli(
        ["network", "har", "stop", str(har_path)],
        session=session_name,
        timeout=timeout,
    )
    steps.append(har_stop_step)
    _record_agent_raw(capture_dir, "har-stop", har_stop_step, artifacts)
    if har_start_step["success"] and har_stop_step["success"]:
        _record_existing_file(har_path, "network_har", artifacts)

    success = all(step["success"] for step in core_steps)
    error = "" if success else next((_step_error(step) for step in core_steps if _step_error(step)), "")
    return {"steps": steps, "artifacts": artifacts, "counts": counts, "success": success, "error": error}


def _derive_recon_root(evidence_root: Path) -> Path:
    """Return the recon root paired with the selected evidence root."""
    if evidence_root == DEFAULT_EVIDENCE_ROOT:
        return DEFAULT_RECON_ROOT
    return evidence_root.parent / "recon"


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
        merge_existing=True,
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
    backend: str = "auto",
) -> dict:
    """为一个 URL 采集浏览器证据，完成后保持命名 session 打开。"""
    selected_backend = resolve_browser_backend(backend)
    target_name = _target_key(target)
    safe_label = _safe_part(label, "capture")
    session_name = session.strip() or default_browser_session(target)
    root = Path(evidence_root) if evidence_root else DEFAULT_EVIDENCE_ROOT
    browser_root = root / target_name / "browser"
    capture_dir = browser_root / f"{_timestamp_slug()}-{safe_label}"
    capture_dir.mkdir(parents=True, exist_ok=True)

    if selected_backend == AGENT_BROWSER_BIN:
        result = _capture_agent_browser_backend(
            url=url,
            session_name=session_name,
            capture_dir=capture_dir,
            timeout=timeout,
            capture_screenshot=capture_screenshot,
        )
    else:
        result = _capture_playwright_backend(
            url=url,
            session_name=session_name,
            capture_dir=capture_dir,
            timeout=timeout,
            capture_screenshot=capture_screenshot,
        )

    steps = result["steps"]
    artifacts = result["artifacts"]
    counts = result["counts"]
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

    summary_path = capture_dir / "summary.json"
    pointer_path = browser_root / "last-capture.json"
    summary = {
        "target": target,
        "target_key": target_name,
        "url": url,
        "session": session_name,
        "label": safe_label,
        "capture_backend": selected_backend,
        "captured_at": _now_utc(),
        "evidence_dir": str(capture_dir),
        "summary_path": str(summary_path),
        "pointer_path": str(pointer_path),
        "success": bool(result["success"]),
        "capture_screenshot": bool(capture_screenshot),
        "counts": counts,
        "artifacts": artifacts,
        "browser_surface": browser_surface,
        "steps": [_compact_step(step) for step in steps],
    }
    if result.get("error"):
        summary["error"] = result["error"]
    _write_json(summary_path, summary)

    pointer = compact_browser_evidence(summary)
    pointer.update(
        {
            "target": target,
            "target_key": target_name,
            "label": safe_label,
            "capture_backend": selected_backend,
        }
    )
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
        "capture_backend": payload.get("capture_backend") or "",
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
