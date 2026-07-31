#!/usr/bin/env python3
"""Evidence-gated Exchange interface checks using the external EBurst tool.

EBurst is an old Python 2 script kept outside this repository.  This module
owns discovery, target scoping, bounded execution, and structured evidence;
it does not import or copy EBurst and does not expose its credential-brute
force mode to Autopilot.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

try:
    from tools.target_paths import canonical_target_value, target_storage_key, url_belongs_to_target
except ImportError:  # pragma: no cover - direct tools/ execution
    from target_paths import canonical_target_value, target_storage_key, url_belongs_to_target  # type: ignore


SCHEMA_VERSION = 1
MAX_HOSTS = 5
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 900
EXCHANGE_PATH_RE = re.compile(
    r"/(?:owa(?:/|$)|ews(?:/|$)|autodiscover(?:/|$)|ecp(?:/|$)|oab(?:/|$)|"
    r"mapi(?:/|$)|rpc(?:/|$)|powershell(?:/|$)|microsoft-server-activesync(?:/|$))",
    re.IGNORECASE,
)
EXCHANGE_TEXT_RE = re.compile(
    r"\b(?:microsoft\s+exchange|outlook\s+web\s+access|autodiscover|"
    r"microsoft-server-activesync|exchange\s+(?:web|mail)|owa|ews)\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SENSITIVE_ENV_KEYS = {
    "BBHUNT_AUTH_HEADERS",
    "BBHUNT_AUTH_HEADER",
    "BBHUNT_COOKIE",
    "BBHUNT_BEARER",
    "BBHUNT_API_KEY",
    "H1_API_TOKEN",
    "CHAOS_API_KEY",
    "RESIN_PROXY_TOKEN",
}
Which = Callable[[str], str | None]
Runner = Callable[..., subprocess.CompletedProcess[str]]


def _shared_tools_dir(env: dict[str, str]) -> Path:
    value = env.get("BBHUNT_TOOLS_DIR") or env.get("OSMEDEUS_TOOLS_DIR")
    return Path(value).expanduser() if value else Path.home() / "Tools"


def _candidate_homes(env: dict[str, str]) -> list[Path]:
    values = []
    explicit = env.get("EBURST_HOME")
    if explicit:
        values.append(Path(explicit).expanduser())
    values.extend(
        [
            _shared_tools_dir(env) / "EBurst",
            Path.home() / "Tools" / "EBurst",
            Path("/root/Tools/EBurst"),
        ]
    )
    seen: set[str] = set()
    result = []
    for value in values:
        key = str(value.resolve())
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def resolve_eburst(*, env: dict[str, str] | None = None, which: Which | None = None) -> dict:
    """Resolve EBurst without importing it or installing dependencies."""
    env = dict(env or os.environ)
    resolver = which or shutil.which
    command = resolver("eburst") or resolver("EBurst")
    if command:
        return {
            "status": "ready",
            "home": str(Path(command).expanduser().parent),
            "script": "",
            "interpreter": str(command),
            "mode": "binary",
        }
    missing_runtime = None
    for home in _candidate_homes(env):
        script = home / "EBurst.py"
        if not script.is_file():
            continue
        candidates = []
        configured = str(env.get("EBURST_PYTHON") or "").strip()
        if configured:
            candidates.append(configured)
        candidates.extend(("python2", "python2.7"))
        interpreter = None
        for item in candidates:
            if os.path.isfile(item) and os.access(item, os.X_OK):
                interpreter = item
                break
            interpreter = resolver(item)
            if interpreter:
                break
        if interpreter:
            return {
                "status": "ready",
                "home": str(home),
                "script": str(script),
                "interpreter": str(interpreter),
                "mode": "python2-script",
            }
        missing_runtime = {
            "status": "missing_interpreter",
            "home": str(home),
            "script": str(script),
            "interpreter": "",
            "reason": "python2-required",
        }
    return missing_runtime or {"status": "missing_script", "home": "", "script": "", "interpreter": ""}


def _read_text(path: Path, *, limit: int = 1_000_000) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _host_url(value: str, target: str) -> tuple[str, str] | None:
    raw = str(value or "").strip().rstrip(".,;)")
    if not raw:
        return None
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
        netloc = parsed.netloc
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not host or not netloc:
        return None
    if not url_belongs_to_target(candidate, target):
        return None
    return candidate, netloc


def _evidence_candidates(recon_dir: Path) -> list[tuple[str, str]]:
    paths = [
        recon_dir / "live" / "technology_inventory.json",
        recon_dir / "live" / "httpx_full.jsonl",
        recon_dir / "live" / "httpx_full.txt",
        recon_dir / "live" / "urls.txt",
        recon_dir / "urls" / "all.txt",
    ]
    evidence = []
    for path in paths:
        content = _read_text(path)
        if content:
            evidence.append((str(path), content))
    return evidence


def detect_exchange_hosts(repo_root: str | Path, target: str, *, max_hosts: int = MAX_HOSTS) -> list[dict]:
    """Find target-owned hosts with Exchange path/product evidence."""
    if max_hosts <= 0:
        return []
    resolved_target = canonical_target_value(target)
    recon_dir = Path(repo_root) / "recon" / target_storage_key(resolved_target)
    found: dict[str, dict] = {}
    for source, content in _evidence_candidates(recon_dir):
        if source.endswith("technology_inventory.json"):
            try:
                payload = json.loads(content)
            except json.JSONDecodeError:
                continue
            records = []
            for host in payload.get("hosts") or []:
                if isinstance(host, dict):
                    records.append(host)
            for item in payload.get("components") or []:
                if isinstance(item, dict):
                    records.append(item)
            for item in records:
                blob = json.dumps(item, ensure_ascii=False)
                if not EXCHANGE_TEXT_RE.search(blob):
                    continue
                value = str(item.get("url") or item.get("host") or "")
                parsed = _host_url(value, resolved_target)
                if parsed:
                    url, netloc = parsed
                    found.setdefault(netloc.lower(), {"url": url, "host": netloc, "evidence": []})[
                        "evidence"
                    ].append(source)
            continue

        for line in content.splitlines():
            if not EXCHANGE_TEXT_RE.search(line) and not EXCHANGE_PATH_RE.search(line):
                continue
            urls = URL_RE.findall(line)
            for value in urls:
                parsed = _host_url(value, resolved_target)
                if not parsed:
                    continue
                url, netloc = parsed
                found.setdefault(netloc.lower(), {"url": url, "host": netloc, "evidence": []})[
                    "evidence"
                ].append(source)
    return list(found.values())[: min(int(max_hosts), MAX_HOSTS)]


def build_probe_command(resolution: dict, host: str) -> list[str]:
    """Build the read-only EBurst interface availability command."""
    if resolution.get("status") != "ready":
        raise ValueError("EBurst is not runnable")
    if not host or "://" in host or "/" in host:
        raise ValueError("EBurst host must be a scoped host[:port], not a URL/path")
    command = [str(resolution["interpreter"])]
    if resolution.get("script"):
        command.append(str(resolution["script"]))
    return command + ["-C", "-d", host]


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temp_path = Path(handle.name)
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.replace(path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def run_exchange_lane(
    repo_root: str | Path,
    target: str,
    *,
    hosts: list[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    max_hosts: int = MAX_HOSTS,
    env: dict[str, str] | None = None,
    which: Which | None = None,
    runner: Runner | None = None,
) -> dict:
    """Run bounded Exchange interface checks and publish a target-owned summary."""
    if timeout < 1 or timeout > MAX_TIMEOUT:
        raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT} seconds")
    if max_hosts < 1 or max_hosts > MAX_HOSTS:
        raise ValueError(f"max_hosts must be between 1 and {MAX_HOSTS}")
    repo = Path(repo_root)
    resolved_target = canonical_target_value(target)
    candidates = []
    if hosts:
        for raw in hosts:
            parsed = _host_url(raw, resolved_target)
            if not parsed:
                raise ValueError(f"EBurst host is outside target scope or invalid: {raw}")
            url, netloc = parsed
            if len(candidates) < max_hosts:
                candidates.append({"url": url, "host": netloc, "evidence": ["explicit-host"]})
    else:
        candidates = detect_exchange_hosts(repo, resolved_target, max_hosts=max_hosts)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "target": resolved_target,
        "lane": "exchange-interface-check",
        "status": "not_applicable" if not candidates else "pending",
        "tool": "eburst",
        "hosts": candidates,
        "results": [],
    }
    resolution = resolve_eburst(env=env, which=which)
    summary["tool_status"] = resolution["status"]
    if not candidates:
        summary["reason"] = "no-exchange-evidence"
    elif resolution.get("status") != "ready":
        summary["status"] = "unavailable"
        summary["reason"] = resolution.get("reason") or resolution["status"]
    else:
        child_env = dict(env or os.environ)
        for key in SENSITIVE_ENV_KEYS:
            child_env.pop(key, None)
        execute = runner or subprocess.run
        for candidate in candidates:
            host = str(candidate["host"])
            result = {"host": host, "url": candidate["url"]}
            try:
                completed = execute(
                    build_probe_command(resolution, host),
                    cwd=resolution["home"],
                    env=child_env,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                result["returncode"] = int(completed.returncode)
                result["status"] = "ok" if completed.returncode == 0 else "failed"
                output = (completed.stdout or "") + (completed.stderr or "")
            except subprocess.TimeoutExpired as exc:
                result.update({"status": "timeout", "returncode": None})
                output = "\n".join(
                    part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part or "")
                    for part in (exc.stdout, exc.stderr)
                )
            raw_dir = repo / "recon" / target_storage_key(resolved_target) / "exchange" / "eburst" / "raw"
            raw_path = raw_dir / (re.sub(r"[^A-Za-z0-9_.-]+", "_", host) + ".txt")
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(str(output or "")[:50_000], encoding="utf-8")
            raw_path.chmod(0o600)
            result["raw_evidence"] = str(raw_path.relative_to(repo))
            summary["results"].append(result)
        statuses = {item["status"] for item in summary["results"]}
        summary["status"] = "ok" if statuses == {"ok"} else "partial" if "ok" in statuses else "failed"

    summary_path = repo / "recon" / target_storage_key(resolved_target) / "exchange" / "eburst" / "summary.json"
    summary["summary_path"] = str(summary_path.relative_to(repo))
    _write_json_atomic(summary_path, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evidence-gated Exchange interface check via external EBurst")
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--host", action="append", default=[], help="Explicit target-owned host[:port] or URL")
    parser.add_argument("--max-hosts", type=int, default=MAX_HOSTS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--json", action="store_true", help="Emit the structured summary (default)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run_exchange_lane(
            args.repo_root,
            args.target,
            hosts=args.host,
            timeout=args.timeout,
            max_hosts=args.max_hosts,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["status"] in {"ok", "not_applicable"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
