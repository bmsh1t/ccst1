#!/usr/bin/env python3
"""按证据调用 Packer-InfoFinder 恢复少量高价值前端异步资源。

该工具不属于 Recon 默认流程。它只把上游工具的恢复结果发布到既有
``recon/<target>/js_dump/``，供 js-reader 和既有证据链继续消费。
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

try:
    from tools.target_paths import (
        canonical_target_value,
        classify_target,
        target_storage_key,
        url_belongs_to_target,
    )
except ImportError:  # pragma: no cover - 兼容 python3 tools/deep_js_packer.py
    from target_paths import (
        canonical_target_value,
        classify_target,
        target_storage_key,
        url_belongs_to_target,
    )


BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = 1
DEFAULT_MAX_BUNDLES = 3
MAX_BUNDLES = 5
DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_SHUJI_TIMEOUT_SECONDS = 120
DEFAULT_RATE_LIMIT = 5
DEFAULT_MAX_WORKERS = 5
DEFAULT_MAX_WORKSPACE_FILES = 500
DEFAULT_MAX_WORKSPACE_BYTES = 200 * 1024 * 1024
SIGNALS = (
    "webpack-runtime",
    "dynamic-import",
    "chunk-map",
    "source-map",
    "minified-unreadable",
    "missing-lazy-chunk",
)
PACKER_DIRNAME = "Packer-InfoFinder(1.6)"
BROWSER_STATUS_FILENAME = "browser-status.json"
SOURCE_MAP_STATUS_FILENAME = "source-map-status.json"
AUTH_ENV_KEYS = {
    "BBHUNT_COOKIE",
    "BBHUNT_BEARER",
    "BBHUNT_API_KEY",
    "BBHUNT_SESSION_ID",
}


@dataclass(frozen=True)
class PackerPaths:
    repo_root: Path
    target: str
    target_key: str

    @property
    def recon_dir(self) -> Path:
        return self.repo_root / "recon" / self.target_key

    @property
    def candidates(self) -> Path:
        return self.recon_dir / "js" / "deep_candidates.txt"

    @property
    def output_dir(self) -> Path:
        return self.recon_dir / "js_dump" / "packer"

    @property
    def manifest(self) -> Path:
        return self.output_dir / "manifest.json"


class _RateLimiter:
    """进程内共享的简单限速器，覆盖上游所有 DownloadJs Session。"""

    def __init__(self, rate: int) -> None:
        self._interval = 1.0 / max(1, rate)
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next_at - now)
            self._next_at = max(now, self._next_at) + self._interval
        if delay:
            time.sleep(delay)


class _RateLimitedSession:
    """包装上游 Session，统一限制下载速率、范围和跳转。"""

    def __init__(self, session: Any, limiter: _RateLimiter, target: str) -> None:
        self._session = session
        self._limiter = limiter
        self._target = target

    def get(self, url: str, *args: Any, **kwargs: Any) -> Any:
        if not url_belongs_to_target(url, self._target):
            raise PermissionError(f"URL outside target scope: {url}")
        self._limiter.wait()
        # 上游默认跟随跨域重定向；本 lane 只消费 target-owned 资源。
        kwargs["allow_redirects"] = False
        return self._session.get(url, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


async def _guard_browser_route(
    route: Any,
    request: Any,
    *,
    limiter: _RateLimiter,
    target: str,
) -> None:
    """限制 Playwright 的 HTTP(S) 子请求；跨目标请求直接终止。"""
    url = str(getattr(request, "url", "") or "")
    if urlsplit(url).scheme.lower() in {"http", "https"}:
        if not url_belongs_to_target(url, target):
            await route.abort()
            return
        await asyncio.to_thread(limiter.wait)
    await route.continue_()


def _install_browser_request_guard(
    limiter: _RateLimiter, target: str, status_path: Path
) -> None:
    """在上游创建 context 时安装统一 scope/rate route。"""
    from playwright.async_api import Browser, Page

    original_new_context = Browser.new_context
    original_goto = Page.goto

    async def guarded_new_context(self: Any, *args: Any, **kwargs: Any) -> Any:
        # context.route 不覆盖 Service Worker 接管的请求，严格 scope 必须禁用它。
        kwargs["service_workers"] = "block"
        try:
            context = await original_new_context(self, *args, **kwargs)
        except Exception as exc:
            _atomic_json(
                status_path,
                {
                    "status": "error",
                    "failure_summary": f"browser context failed: {_safe_summary(exc)}",
                },
            )
            raise

        async def handle(route: Any, request: Any) -> None:
            await _guard_browser_route(
                route,
                request,
                limiter=limiter,
                target=target,
            )

        await context.route("**/*", handle)
        return context

    async def guarded_goto(self: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            response = await original_goto(self, *args, **kwargs)
        except Exception as exc:
            _atomic_json(
                status_path,
                {
                    "status": "error",
                    "failure_summary": f"browser navigation failed: {_safe_summary(exc)}",
                },
            )
            raise
        _atomic_json(status_path, {"status": "ok", "failure_summary": ""})
        return response

    Browser.new_context = guarded_new_context
    Page.goto = guarded_goto


def _read_browser_status(path: Path) -> dict[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "error",
            "failure_summary": f"browser status unavailable: {_safe_summary(exc)}",
        }
    if not isinstance(payload, dict) or payload.get("status") not in {"ok", "error"}:
        return {
            "status": "error",
            "failure_summary": "browser status artifact is invalid",
        }
    return {
        "status": str(payload["status"]),
        "failure_summary": _safe_summary(payload.get("failure_summary")),
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_summary(value: object, limit: int = 400) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]


def _safe_source_name(source: str, content: str, position: str) -> str:
    """Return a unique flat filename that survives Shuji's basename handling."""
    basename = re.split(r"[\\\\/]", source.split("?", 1)[0])[-1]
    basename = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._") or "source.js"
    basename = basename[-120:]
    digest = hashlib.sha256(f"{source}\0{content}".encode("utf-8")).hexdigest()[:12]
    return f"source_{position.replace('.', '_')}_{digest}_{basename}"


def _normalize_source_map(map_bytes: bytes) -> bytes:
    """Make untrusted Source Map names flat before passing them to Shuji."""
    try:
        payload = json.loads(map_bytes.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid Source Map JSON: {_safe_summary(exc)}") from exc

    def normalize(mapping: object, position: str) -> None:
        if not isinstance(mapping, dict):
            raise ValueError("invalid Source Map shape")
        if mapping.get("version") != 3:
            raise ValueError("Source Map requires version 3")
        mapping["sourceRoot"] = ""
        has_sources = "sources" in mapping or "sourcesContent" in mapping
        has_sections = "sections" in mapping
        if has_sources and has_sections:
            raise ValueError("Source Map cannot mix sources with indexed sections")
        if has_sections:
            sections = mapping["sections"]
            if not isinstance(sections, list):
                raise ValueError("invalid indexed Source Map sections")
            for index, section in enumerate(sections):
                offset = section.get("offset") if isinstance(section, dict) else None
                if (
                    not isinstance(section, dict)
                    or not isinstance(offset, dict)
                    or not all(
                        isinstance(offset.get(key), int)
                        and not isinstance(offset.get(key), bool)
                        and offset[key] >= 0
                        for key in ("line", "column")
                    )
                    or "map" not in section
                ):
                    raise ValueError("invalid indexed Source Map section")
                normalize(section["map"], f"{position}.{index}")
            return
        if has_sources:
            sources = mapping.get("sources")
            contents = mapping.get("sourcesContent")
            if (
                not isinstance(sources, list)
                or not isinstance(contents, list)
                or len(sources) != len(contents)
                or not all(isinstance(source, str) for source in sources)
                or not all(isinstance(content, str) for content in contents)
            ):
                raise ValueError("Source Map requires aligned string sources and sourcesContent")
            mapping["sources"] = [
                _safe_source_name(source, content, f"{position}.{index}")
                for index, (source, content) in enumerate(zip(sources, contents))
            ]
        if not has_sources:
            raise ValueError("Source Map requires aligned string sources and sourcesContent")

    normalize(payload, "0")
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class _SourceMapStatus:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.attempts = 0
        self.successes = 0
        self.unavailable = False
        self.failures: list[str] = []
        self._write()

    def record(self, *, success: bool, failure: object = "", unavailable: bool = False) -> None:
        with self.lock:
            self.attempts += 1
            self.successes += int(success)
            self.unavailable |= unavailable
            if not success:
                self.failures.append(_safe_summary(failure))
            self._write()

    def _write(self) -> None:
        if not self.attempts:
            status = "skipped"
        elif self.successes and self.failures:
            status = "partial"
        elif self.successes:
            status = "ok"
        elif self.unavailable:
            status = "unavailable"
        else:
            status = "error"
        _atomic_json(
            self.path,
            {
                "status": status,
                "failure_summary": _safe_summary("; ".join(self.failures)),
                "attempts": self.attempts,
                "successes": self.successes,
            },
        )


def _read_source_map_status(path: Path) -> dict[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "error",
            "failure_summary": f"Source Map status unavailable: {_safe_summary(exc)}",
        }
    status = payload.get("status") if isinstance(payload, dict) else None
    if status not in {"skipped", "ok", "partial", "unavailable", "error"}:
        return {"status": "error", "failure_summary": "Source Map status artifact is invalid"}
    return {"status": status, "failure_summary": _safe_summary(payload.get("failure_summary"))}


def _read_lines(path: Path) -> list[str]:
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def _is_http_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
    )


def _bundle_score(url: str) -> tuple[int, str]:
    name = (urlsplit(url).path or "").lower()
    signals = (
        "runtime",
        "webpack",
        "manifest",
        "main",
        "app",
        "index",
        "bundle",
        "chunk",
    )
    return (sum(token in name for token in signals), url)


def select_bundle_urls(
    target: str,
    candidates_path: Path,
    *,
    explicit_urls: list[str] | None = None,
    max_bundles: int = DEFAULT_MAX_BUNDLES,
) -> list[str]:
    """选择少量 target-owned bundle；原始候选文件始终保持不变。"""
    if not 1 <= max_bundles <= MAX_BUNDLES:
        raise ValueError(f"max_bundles must be between 1 and {MAX_BUNDLES}")

    source = explicit_urls if explicit_urls else _read_lines(candidates_path)
    selected: list[str] = []
    seen: set[str] = set()
    for raw in source:
        value = raw.strip()
        if not value or value in seen:
            continue
        if not _is_http_url(value):
            if explicit_urls:
                raise ValueError(f"invalid bundle URL: {value}")
            continue
        if not url_belongs_to_target(value, target):
            if explicit_urls:
                raise ValueError(f"bundle URL is outside target scope: {value}")
            continue
        seen.add(value)
        selected.append(value)

    if explicit_urls:
        if len(selected) > max_bundles:
            raise ValueError(f"at most {max_bundles} bundle URLs are allowed")
        return selected
    return sorted(
        selected, key=lambda value: (-_bundle_score(value)[0], _bundle_score(value)[1])
    )[:max_bundles]


def resolve_tool_root(explicit: str = "") -> Path | None:
    candidates = (
        [explicit]
        if explicit
        else [
            os.environ.get("PACKER_INFOFINDER_HOME", ""),
            str(Path.home() / "Tools" / PACKER_DIRNAME),
        ]
    )
    for raw in candidates:
        path = Path(raw).expanduser() if raw else None
        if (
            path
            and (path / "Packer-InfoFinder.py").is_file()
            and (path / "lib" / "DownloadJs.py").is_file()
        ):
            return path.resolve()
    return None


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    except Exception:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise


def _base_result(
    paths: PackerPaths,
    mode: str,
    signal_name: str,
    evidence_ref: str,
    browser: bool,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "packer-infofinder",
        "target": paths.target,
        "target_key": paths.target_key,
        "mode": mode,
        "signal": signal_name,
        "evidence_ref": evidence_ref,
        "generated_at": _utc_now(),
        "status": "skipped",
        "input_urls": [],
        "duration_seconds": 0.0,
        "recovered_files": 0,
        "reused_files": 0,
        "raw_artifacts": 0,
        "browser_requested": browser,
        "browser_status": "skipped",
        "browser_failure_summary": "",
        "source_map_status": "skipped",
        "source_map_failure_summary": "",
        "failure_summary": "",
    }


def _normalize_evidence_ref(repo_root: Path, evidence_ref: str) -> str:
    root = repo_root.resolve()
    raw_path = Path(evidence_ref.strip()).expanduser()
    resolved = (raw_path if raw_path.is_absolute() else root / raw_path).resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("evidence_ref must stay inside repo_root") from exc
    if not resolved.exists():
        raise ValueError(f"evidence_ref does not exist: {relative}")
    return str(relative)


def _workspace_usage(root: Path) -> tuple[int, int]:
    files = 0
    total_bytes = 0
    if not root.exists():
        return files, total_bytes
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                files += 1
                total_bytes += path.stat().st_size
        except OSError:
            continue
    return files, total_bytes


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=3)


def _copy_recovered_artifacts(
    work_dir: Path, output_dir: Path
) -> tuple[int, int, int, list[str]]:
    """以哈希命名发布上游文件，避免覆盖既有 js_dump 证据。"""
    source_root = work_dir / "tmp"
    if not source_root.is_dir():
        return 0, 0, 0, []

    files_dir = output_dir / "files"
    raw_dir = output_dir / "raw"
    files_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    recovered = 0
    reused = 0
    raw_artifacts = 0
    published: list[str] = []
    for source in sorted(source_root.rglob("*")):
        if not source.is_file() or source.is_symlink():
            continue
        try:
            content = source.read_bytes()
        except OSError:
            continue
        digest = hashlib.sha256(content).hexdigest()
        # Packer 会为下载文件加六位随机前缀；去掉后保留对 AI 有用的语义文件名。
        source_name = re.sub(r"^[A-Za-z0-9]{6}\.(?=[^.]+\.)", "", source.name)
        name = (
            "".join(
                char if char.isalnum() or char in ".-_" else "_" for char in source_name
            )
            or "artifact"
        )
        # JS/source files continue into js-reader; HTML/SQLite stay原始附件，不解析为第二套 schema。
        is_recovered_source = source.suffix.lower() in {
            ".js",
            ".mjs",
            ".cjs",
            ".map",
            ".ts",
            ".tsx",
            ".vue",
        }
        destination_dir = files_dir if is_recovered_source else raw_dir
        existing = next(iter(sorted(destination_dir.glob(f"{digest[:16]}_*"))), None)
        destination = existing or destination_dir / f"{digest[:16]}_{name}"
        if is_recovered_source and existing is not None:
            reused += 1
        elif is_recovered_source:
            destination.write_bytes(content)
            recovered += 1
        elif existing is None:
            destination.write_bytes(content)
            raw_artifacts += 1
        else:
            raw_artifacts += 1
        published.append(str(destination))
    return recovered, reused, raw_artifacts, published


def _copy_tool_config(tool_root: Path, work_dir: Path) -> None:
    config = tool_root / "config.ini"
    if config.is_file():
        shutil.copy2(config, work_dir / "config.ini")


def _run_worker(
    work_dir: Path,
    spec_path: Path,
    *,
    timeout: int,
) -> tuple[int, str]:
    log_path = work_dir / "packer.log"
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("BBHUNT_AUTH_") and key not in AUTH_ENV_KEYS
    }
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        "--spec",
        str(spec_path),
    ]
    with log_path.open("wb") as log_handle:
        process = subprocess.Popen(
            command,
            cwd=work_dir,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        started = time.monotonic()
        reason = ""
        while process.poll() is None:
            if time.monotonic() - started > timeout:
                reason = f"worker timed out after {timeout}s"
                _kill_process_group(process)
                break
            file_count, byte_count = _workspace_usage(work_dir)
            if (
                file_count > DEFAULT_MAX_WORKSPACE_FILES
                or byte_count > DEFAULT_MAX_WORKSPACE_BYTES
            ):
                reason = (
                    "worker reached workspace budget "
                    f"(files={file_count}, bytes={byte_count})"
                )
                _kill_process_group(process)
                break
            time.sleep(0.2)
        if process.poll() is None:
            _kill_process_group(process)
        return process.returncode if process.returncode is not None else 1, reason


def run_packer(
    target: str,
    *,
    mode: str,
    signal_name: str,
    evidence_ref: str,
    explicit_urls: list[str] | None = None,
    max_bundles: int = DEFAULT_MAX_BUNDLES,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    browser: bool = False,
    tool_root: str = "",
    repo_root: str | Path = BASE_DIR,
) -> dict[str, Any]:
    """执行一次隔离恢复；所有失败都显式落入目标 artifact manifest。"""
    if mode not in {"bundle", "page"}:
        raise ValueError(f"unsupported mode: {mode}")
    if signal_name not in SIGNALS:
        raise ValueError(f"unsupported signal: {signal_name}")
    if not evidence_ref.strip():
        raise ValueError("evidence_ref is required")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if browser and mode != "page":
        raise ValueError("--browser is only valid in page mode")
    target_info = classify_target(canonical_target_value(target))
    if target_info["kind"] in {"list", "cidr"}:
        raise ValueError("Packer deep-JS lane requires one domain, URL, or IP target")

    resolved_target = canonical_target_value(target)
    paths = PackerPaths(
        Path(repo_root).resolve(), resolved_target, target_storage_key(resolved_target)
    )
    normalized_evidence_ref = _normalize_evidence_ref(paths.repo_root, evidence_ref)
    result = _base_result(
        paths, mode, signal_name, normalized_evidence_ref, browser
    )
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        if mode == "page":
            if len(explicit_urls or []) != 1:
                raise ValueError("page mode requires exactly one --url entry URL")
            selected_urls = select_bundle_urls(
                resolved_target,
                paths.candidates,
                explicit_urls=explicit_urls,
                max_bundles=1,
            )
        else:
            selected_urls = select_bundle_urls(
                resolved_target,
                paths.candidates,
                explicit_urls=explicit_urls,
                max_bundles=max_bundles,
            )
        result["input_urls"] = selected_urls
        if not selected_urls:
            result["failure_summary"] = (
                "no target-owned JS bundle candidates were available"
            )
            return result

        resolved_tool_root = resolve_tool_root(tool_root)
        if resolved_tool_root is None:
            result["status"] = "unavailable"
            result["failure_summary"] = "Packer-InfoFinder installation is unavailable"
            return result

        with tempfile.TemporaryDirectory(
            prefix="packer-infofinder-", dir=paths.output_dir
        ) as temp_dir:
            work_dir = Path(temp_dir)
            _copy_tool_config(resolved_tool_root, work_dir)
            spec = {
                "tool_root": str(resolved_tool_root),
                "target": resolved_target,
                "mode": mode,
                "urls": selected_urls,
                "browser": bool(browser and mode == "page"),
                "max_workers": DEFAULT_MAX_WORKERS,
                "rate_limit": DEFAULT_RATE_LIMIT,
                "timeout": timeout,
            }
            spec_path = work_dir / "worker-spec.json"
            _atomic_json(spec_path, spec)
            return_code, stop_reason = _run_worker(work_dir, spec_path, timeout=timeout)
            if browser:
                browser_result = _read_browser_status(
                    work_dir / BROWSER_STATUS_FILENAME
                )
                result["browser_status"] = browser_result["status"]
                result["browser_failure_summary"] = browser_result[
                    "failure_summary"
                ]
            source_map_result = _read_source_map_status(
                work_dir / SOURCE_MAP_STATUS_FILENAME
            )
            result["source_map_status"] = source_map_result["status"]
            result["source_map_failure_summary"] = source_map_result["failure_summary"]
            recovered, reused, raw_artifacts, published = _copy_recovered_artifacts(
                work_dir, paths.output_dir
            )
            result["recovered_files"] = recovered
            result["reused_files"] = reused
            result["raw_artifacts"] = raw_artifacts
            result["published_artifacts"] = [
                str(Path(item).relative_to(paths.repo_root)) for item in published
            ]
            log_path = work_dir / "packer.log"
            if log_path.is_file():
                (paths.output_dir / "raw").mkdir(parents=True, exist_ok=True)
                log_destination = (
                    paths.output_dir / "raw" / f"{time.time_ns()}_packer.log"
                )
                shutil.copy2(log_path, log_destination)
                result["log_artifact"] = str(
                    log_destination.relative_to(paths.repo_root)
                )
            if stop_reason:
                result["status"] = (
                    "partial" if recovered or reused or raw_artifacts else "error"
                )
                result["failure_summary"] = stop_reason
            elif browser and result["browser_status"] != "ok":
                result["status"] = (
                    "partial" if recovered or reused or raw_artifacts else "error"
                )
                result["failure_summary"] = result["browser_failure_summary"]
                if return_code != 0:
                    result["failure_summary"] += (
                        f"; worker exited with code {return_code}"
                    )
            elif return_code == 0 and (recovered or reused):
                result["status"] = "ok"
            elif return_code == 0:
                result["status"] = "partial"
                result["failure_summary"] = (
                    "Packer worker completed without recovered source files"
                )
            else:
                result["status"] = (
                    "partial" if recovered or reused or raw_artifacts else "error"
                )
                result["failure_summary"] = (
                    f"Packer worker exited with code {return_code}"
                )
            if result["source_map_status"] in {"partial", "unavailable", "error"}:
                result["status"] = (
                    "partial" if recovered or reused or raw_artifacts else "error"
                )
                source_map_failure = result["source_map_failure_summary"]
                if source_map_failure:
                    source_map_failure = f"Source Map: {source_map_failure}"
                else:
                    source_map_failure = f"Source Map restoration {result['source_map_status']}"
                result["failure_summary"] = "; ".join(
                    item for item in (result["failure_summary"], source_map_failure) if item
                )
    except ValueError:
        raise
    except Exception as exc:
        result["status"] = "error"
        result["failure_summary"] = _safe_summary(exc)
    finally:
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        _atomic_json(paths.manifest, result)
    return result


def _load_worker_spec(path: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid worker spec: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid worker spec payload")
    return payload


def worker_main(spec_path: str) -> int:
    """在子进程内对上游私有模块施加 scope、匿名、并发和速率限制。"""
    spec = _load_worker_spec(spec_path)
    tool_root = Path(str(spec.get("tool_root") or ""))
    target = str(spec.get("target") or "")
    mode = str(spec.get("mode") or "")
    urls = [str(value) for value in spec.get("urls", []) if isinstance(value, str)]
    if (
        not tool_root.is_dir()
        or not target
        or mode not in {"bundle", "page"}
        or not urls
    ):
        raise ValueError("worker spec is missing required fields")
    sys.path.insert(0, str(BASE_DIR))
    sys.path.insert(0, str(tool_root))

    import requests
    from lib import DownloadJs as download_module  # type: ignore

    limiter = _RateLimiter(int(spec.get("rate_limit") or DEFAULT_RATE_LIMIT))
    direct_session = requests.Session()
    direct_session.trust_env = False
    original_executor = download_module.ThreadPoolExecutor
    original_init = download_module.DownloadJs.__init__
    original_sane_url = download_module.DownloadJs._is_sane_js_url
    original_restore = getattr(
        download_module.DownloadJs, "_restore_sources_with_reverse_sourcemap", None
    )
    if not callable(original_restore):
        raise RuntimeError("Packer Source Map helper is unavailable")
    source_map_status = _SourceMapStatus(Path.cwd() / SOURCE_MAP_STATUS_FILENAME)
    shuji_timeout = max(
        1,
        min(
            DEFAULT_SHUJI_TIMEOUT_SECONDS,
            int(spec.get("timeout") or DEFAULT_TIMEOUT_SECONDS) - 1,
        ),
    )

    def bounded_executor(*args: Any, **kwargs: Any) -> Any:
        requested = kwargs.pop("max_workers", args[0] if args else DEFAULT_MAX_WORKERS)
        remaining_args = args[1:] if args else ()
        kwargs["max_workers"] = min(
            max(1, int(requested)), int(spec.get("max_workers") or DEFAULT_MAX_WORKERS)
        )
        return original_executor(*remaining_args, **kwargs)

    def bounded_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        if hasattr(self.session, "trust_env"):
            self.session.trust_env = False
        self.session = _RateLimitedSession(self.session, limiter, target)

    def scoped_url(self: Any, url: str) -> bool:
        return bool(original_sane_url(self, url) and url_belongs_to_target(url, target))

    def scoped_get(*args: Any, **kwargs: Any) -> Any:
        url = str(kwargs.get("url") or (args[0] if args else ""))
        if not url_belongs_to_target(url, target):
            raise requests.exceptions.RequestException(
                f"URL outside target scope: {url}"
            )
        limiter.wait()
        kwargs["allow_redirects"] = False
        return direct_session.get(*args, **kwargs)

    def restore_with_shuji(
        self: Any, map_bytes: object, map_name: object, project_root: object
    ) -> tuple[str, int, int]:
        try:
            normalized = _normalize_source_map(bytes(map_bytes))
            safe_map_name = re.sub(
                r'[:*?"<>|/\\\\]+', "_", re.split(r"[\\\\/]", str(map_name or ""))[-1]
            ) or "unknown.map"
            if not safe_map_name.endswith(".map"):
                safe_map_name += ".map"
            workspace = Path.cwd().resolve()
            output_dir = (Path(str(project_root)) / "sourcemaps" / safe_map_name).resolve()
            output_dir.relative_to(workspace)
            output_dir.mkdir(parents=True, exist_ok=True)
            before = sum(1 for path in output_dir.rglob("*") if path.is_file())
            input_path = output_dir / f".shuji_input_{time.time_ns()}_{threading.get_ident()}.map"
            try:
                input_path.write_bytes(normalized)
                shuji = shutil.which("shuji")
                if not shuji:
                    raise FileNotFoundError("shuji@0.8.0 command is unavailable")
                try:
                    completed = subprocess.run(
                        [shuji, input_path.name, "-o", ".", "-v"],
                        cwd=output_dir,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        check=False,
                        timeout=shuji_timeout,
                    )
                except subprocess.TimeoutExpired as exc:
                    raise TimeoutError(
                        f"shuji timed out after {shuji_timeout}s"
                    ) from exc
                if completed.stdout:
                    print(completed.stdout, end="", file=sys.stderr)
                if completed.stderr:
                    print(completed.stderr, end="", file=sys.stderr)
                if completed.returncode:
                    detail = _safe_summary(completed.stderr or completed.stdout or "unknown error")
                    raise RuntimeError(f"shuji exited with code {completed.returncode}: {detail}")
            finally:
                input_path.unlink(missing_ok=True)
            after = sum(1 for path in output_dir.rglob("*") if path.is_file())
            created = max(0, after - before)
            if not after:
                raise RuntimeError("shuji completed without recovered source files")
        except FileNotFoundError as exc:
            source_map_status.record(success=False, failure=exc, unavailable=True)
            raise
        except Exception as exc:
            source_map_status.record(success=False, failure=exc)
            raise
        source_map_status.record(success=True)
        return str(output_dir), created, after

    requests.get = scoped_get
    download_module.ThreadPoolExecutor = bounded_executor
    download_module.DownloadJs.__init__ = bounded_init
    download_module.DownloadJs._is_sane_js_url = scoped_url
    download_module.DownloadJs._restore_sources_with_reverse_sourcemap = restore_with_shuji
    if bool(spec.get("browser")) and mode == "page":
        browser_status_path = Path.cwd() / BROWSER_STATUS_FILENAME
        _atomic_json(
            browser_status_path,
            {"status": "error", "failure_summary": "browser stage did not complete"},
        )
        try:
            _install_browser_request_guard(limiter, target, browser_status_path)
        except Exception as exc:
            # 浏览器是可选增强；记录失败后仍允许上游完成静态恢复。
            _atomic_json(
                browser_status_path,
                {
                    "status": "error",
                    "failure_summary": f"browser guard setup failed: {_safe_summary(exc)}",
                },
            )
    options = SimpleNamespace(
        url=urls[0] if mode == "page" else None,
        cookie=None,
        head="Cache-Control:no-cache",
        list=None,
        proxy=None,
        js=",".join(urls) if mode == "bundle" else None,
        ssl_flag="1",
        silent="adapter",
        finder=mode == "page",
        url_timeout=0,
        browser=bool(spec.get("browser")) if mode == "page" else False,
        browser_timeout=10000,
        max_iframe_depth=3,
        no_iframe=False,
        dom_scan_max_chars=900000,
    )
    if mode == "bundle":
        from lib.runner import js_only_scan  # type: ignore

        # 上游 JS-only runner 的 IP 连通性探测与目标扫描无关，明确禁用。
        js_only_scan.testProxy = lambda _options, _show: ""
        js_only_scan.run_js_only_scan(options)
    else:
        from lib.Controller import Project  # type: ignore

        Project(urls[0], options).parseStart()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evidence-gated Packer-InfoFinder deep-JS adapter"
    )
    parser.add_argument("--target", help="Single target used under recon/<target>/")
    parser.add_argument("--mode", choices=("bundle", "page"), default="bundle")
    parser.add_argument("--signal", choices=SIGNALS, help="Observed deep-JS trigger")
    parser.add_argument("--evidence-ref", help="Artifact path supporting the trigger")
    parser.add_argument(
        "--url",
        action="append",
        default=[],
        help="Target-owned bundle URL; page mode requires exactly one",
    )
    parser.add_argument(
        "--max-bundles",
        type=int,
        default=DEFAULT_MAX_BUNDLES,
        choices=range(1, MAX_BUNDLES + 1),
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Page mode only; use after observing dynamic script loading",
    )
    parser.add_argument(
        "--tool-root", default="", help="Optional local Packer-InfoFinder root"
    )
    parser.add_argument("--repo-root", default=str(BASE_DIR), help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Print the manifest JSON")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--spec", default="", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.worker:
        if not args.spec:
            raise SystemExit("--worker requires --spec")
        return worker_main(args.spec)
    if not args.target:
        print("error: --target is required", file=sys.stderr)
        return 2
    if not args.signal:
        print("error: --signal is required", file=sys.stderr)
        return 2
    if not args.evidence_ref:
        print("error: --evidence-ref is required", file=sys.stderr)
        return 2
    try:
        result = run_packer(
            args.target,
            mode=args.mode,
            signal_name=args.signal,
            evidence_ref=args.evidence_ref,
            explicit_urls=args.url,
            max_bundles=args.max_bundles,
            timeout=args.timeout,
            browser=args.browser,
            tool_root=args.tool_root,
            repo_root=args.repo_root,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(result, ensure_ascii=False, sort_keys=True)
        if args.json
        else f"{result['status']}: {result['failure_summary']}"
    )
    return 0 if result["status"] in {"ok", "skipped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
